<?php
/**
 * API Client Class for ReportedIP Service.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_API {

	private static $instance = null;

	private $api_key;
	private $api_endpoint;
	private $timeout;
	private $timeout_reputation = 5;
	private $cache;
	private $logger;
	private $mode_manager;

	/**
	 * Get singleton instance
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function __construct() {
		$this->api_key      = get_option( 'reportedip_hive_api_key', '' );
		$this->api_endpoint = get_option( 'reportedip_hive_api_endpoint', 'https://reportedip.de/wp-json/reportedip/v2/' );
		$this->timeout      = 30;
		$this->cache        = ReportedIP_Hive_Cache::get_instance();
		$this->logger       = ReportedIP_Hive_Logger::get_instance();
		$this->mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
	}

	/**
	 * Check if API can be used based on mode and configuration
	 *
	 * @return bool
	 */
	public function can_use_api() {
		if ( ! $this->mode_manager->can_use_api() ) {
			return false;
		}

		return $this->is_configured();
	}

	/**
	 * Check if API is configured
	 */
	public function is_configured() {
		return ! empty( $this->api_key ) && ! empty( $this->api_endpoint );
	}

	/**
	 * Test API connection
	 */
	public function test_connection() {
		if ( ! $this->is_configured() ) {
			return array(
				'success' => false,
				'message' => __( 'API key or endpoint not configured.', 'reportedip-hive' ),
			);
		}

		$response = $this->make_request( 'GET', 'verify-key' );

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => $response->get_error_message(),
			);
		}

		$body          = wp_remote_retrieve_body( $response );
		$data          = json_decode( $body, true );
		$response_code = wp_remote_retrieve_response_code( $response );

		if ( $response_code === 200 && isset( $data['data'] ) && isset( $data['data']['valid'] ) ) {
			$key_data = $data['data'];

			if ( $key_data['valid'] === true ) {
				$report_limit          = isset( $key_data['limits']['dailyReportLimit'] ) ? intval( $key_data['limits']['dailyReportLimit'] ) : -1;
				$has_report_permission = $report_limit !== 0;

				$response = array(
					'success'               => true,
					'message'               => __( 'API key verified successfully!', 'reportedip-hive' ),
					'key_name'              => $key_data['keyName'] ?? 'Unknown',
					'user_role'             => $key_data['userRole'] ?? 'Unknown',
					'permissions'           => $key_data['permissions'] ?? array(),
					'limits'                => $key_data['limits'] ?? array(),
					'features'              => $key_data['features'] ?? array(),
					'daily_limit'           => isset( $key_data['limits']['dailyApiLimit'] ) ? $key_data['limits']['dailyApiLimit'] : 'Unknown',
					'remaining_calls'       => isset( $key_data['limits']['remainingApiCalls'] ) ? $key_data['limits']['remainingApiCalls'] : 'Unknown',
					'report_limit'          => $report_limit,
					'has_report_permission' => $has_report_permission,
				);

				if ( ! $has_report_permission ) {
					$response['warning']      = __( 'Your API key currently has no report permission. Security events will be logged locally but not reported to the service. Upgrade to Contributor or higher to enable full reporting.', 'reportedip-hive' );
					$response['warning_code'] = 'no_report_permission';
				}

				return $response;
			} else {
				return array(
					'success' => false,
					'message' => __( 'API key is invalid or expired.', 'reportedip-hive' ),
				);
			}
		} elseif ( $response_code === 401 || $response_code === 403 ) {
			return array(
				'success' => false,
				'message' => __( 'API key authentication failed. Please check your API key.', 'reportedip-hive' ),
			);
		} elseif ( $response_code === 429 ) {
			return array(
				'success' => false,
				'message' => __( 'API rate limit exceeded. Please try again later.', 'reportedip-hive' ),
			);
		}

		return array(
			'success'       => false,
			'message'       => __( 'Invalid API response or server error.', 'reportedip-hive' ),
			'response_code' => $response_code,
		);
	}

	/**
	 * Check IP reputation with caching
	 *
	 * In local mode, this method returns false immediately without making API calls.
	 * In community mode, it checks reputation against the service.
	 *
	 * @param string $ip_address IP address to check
	 * @param bool   $verbose Whether to get verbose response
	 * @return array|false Reputation data or false if unavailable
	 */
	public function check_ip_reputation( $ip_address, $verbose = false ) {
		if ( ! $this->can_use_api() ) {
			if ( $this->mode_manager->is_local_mode() ) {
				return false;
			}
			$this->track_api_call( false, 0, 'not_configured' );
			return false;
		}

		$cached_result = $this->cache->get_reputation( $ip_address );
		if ( $cached_result !== false ) {
			return isset( $cached_result['data'] ) ? $cached_result['data'] : $cached_result;
		}

		if ( $this->is_rate_limited() ) {
			$this->track_api_call( false, 0, 'rate_limited' );
			$this->logger->log_security_event(
				'api_rate_limited',
				$ip_address,
				array(
					'reason' => 'Rate limit active, skipping API call',
				),
				'medium'
			);
			return false;
		}

		$start_time = microtime( true );

		$params = array(
			'ip'      => $ip_address,
			'verbose' => $verbose ? 'true' : 'false',
		);

		$response      = $this->make_request( 'GET', 'check', $params, null, $this->timeout_reputation );
		$response_time = round( ( microtime( true ) - $start_time ) * 1000, 2 );

		if ( is_wp_error( $response ) ) {
			$error_message = $response->get_error_message();
			$this->track_api_call( false, $response_time, 'wp_error' );

			$this->logger->log_security_event(
				'api_error',
				$ip_address,
				array(
					'error'         => $error_message,
					'response_time' => $response_time,
					'endpoint'      => 'check',
				),
				'medium'
			);

			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Plugin diagnostic logging; debug.log only.
			error_log( 'ReportedIP Hive: IP check failed - ' . $error_message );

			$this->cache->set_reputation( $ip_address, false, true );
			return false;
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		$body          = wp_remote_retrieve_body( $response );
		$data          = json_decode( $body, true );

		if ( $response_code === 429 ) {
			$retry_after = wp_remote_retrieve_header( $response, 'retry-after' );
			$reset_time  = time() + ( $retry_after ? intval( $retry_after ) : 3600 );
			$this->set_rate_limited( $reset_time );

			$this->track_api_call( false, $response_time, 'rate_limit_429' );
			$this->logger->log_security_event(
				'api_rate_limit_hit',
				$ip_address,
				array(
					'retry_after' => $retry_after,
					'reset_time'  => gmdate( 'Y-m-d H:i:s', $reset_time ),
				),
				'high'
			);

			return false;
		}

		if ( $response_code === 200 && isset( $data['data'] ) ) {
			$this->track_api_call( true, $response_time, null );

			$this->cache->set_reputation( $ip_address, $data['data'] );

			if ( get_option( 'reportedip_hive_detailed_logging', false ) ) {
				$this->logger->log_security_event(
					'api_success',
					$ip_address,
					array(
						'response_time' => $response_time,
						'endpoint'      => 'check',
						'confidence'    => $data['data']['abuseConfidencePercentage'] ?? 'unknown',
					),
					'low'
				);
			}

			return $data['data'];
		}

		$this->track_api_call( false, $response_time, 'invalid_response' );
		$this->logger->log_security_event(
			'api_invalid_response',
			$ip_address,
			array(
				'response_code' => $response_code,
				'response_time' => $response_time,
				'body_preview'  => substr( $body, 0, 200 ),
			),
			'medium'
		);

		$this->cache->set_reputation( $ip_address, false, true );
		return false;
	}

	/**
	 * Report IP to API
	 *
	 * In local mode, this method returns success=false with a mode message.
	 * In community mode, it reports the IP to the service.
	 *
	 * @param string       $ip_address IP address to report
	 * @param array|string $category_ids Category ID(s)
	 * @param string       $comment Report comment
	 * @return array Result with success status
	 */
	public function report_ip( $ip_address, $category_ids, $comment = '' ) {
		if ( ! $this->can_use_api() ) {
			if ( $this->mode_manager->is_local_mode() ) {
				return array(
					'success'    => false,
					'message'    => __( 'API reports disabled in Local Mode', 'reportedip-hive' ),
					'local_mode' => true,
				);
			}
			return array(
				'success' => false,
				'message' => __( 'API not configured', 'reportedip-hive' ),
			);
		}

		if ( ! $this->has_report_quota() ) {
			$quota_status = $this->get_quota_status();
			return array(
				'success'         => false,
				'message'         => $quota_status['message'],
				'quota_exhausted' => true,
				'reset_time'      => $quota_status['reset_time'],
				'reason'          => $quota_status['reason'],
			);
		}

		$data = array(
			'ip'         => $ip_address,
			'categories' => is_array( $category_ids ) ? implode( ',', $category_ids ) : $category_ids,
			'comment'    => $comment,
		);

		$response = $this->make_request( 'POST', 'report', array(), $data );

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => $response->get_error_message(),
			);
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		$body          = wp_remote_retrieve_body( $response );
		$response_data = json_decode( $body, true );

		if ( $response_code === 200 && isset( $response_data['data'] ) ) {
			$this->decrement_quota_counter();

			return array(
				'success' => true,
				'data'    => $response_data['data'],
			);
		} elseif ( $response_code === 429 ) {
			return array(
				'success'     => false,
				'message'     => 'Rate limit exceeded',
				'retry_after' => wp_remote_retrieve_header( $response, 'retry-after' ),
			);
		} else {
			$error_message = 'Unknown error';
			if ( isset( $response_data['message'] ) ) {
				$error_message = $response_data['message'];
			} elseif ( isset( $response_data['code'] ) ) {
				$error_message = $response_data['code'];
			}

			return array(
				'success'       => false,
				'message'       => $error_message,
				'response_code' => $response_code,
			);
		}
	}

	/**
	 * Report positive feedback (whitelist/unblock)
	 */
	public function report_positive_feedback( $ip_address, $reason = '' ) {
		if ( ! $this->is_configured() ) {
			return false;
		}

		$data = array(
			'ipAddress' => $ip_address,
			'reason'    => $reason,
		);

		$response = $this->make_request( 'POST', 'whitelist', array(), $data );

		if ( is_wp_error( $response ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Plugin diagnostic logging; debug.log only.
			error_log( "ReportedIP Hive: Positive feedback for $ip_address - $reason" );
			return false;
		}

		$response_code = wp_remote_retrieve_response_code( $response );

		if ( $response_code === 403 ) {
			return array( 'success' => false );
		}

		return $response_code === 200;
	}

	/**
	 * Get threat categories
	 */
	public function get_categories() {
		if ( ! $this->is_configured() ) {
			return false;
		}

		$response = $this->make_request( 'GET', 'categories' );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( wp_remote_retrieve_response_code( $response ) === 200 && isset( $data['data'] ) ) {
			return $data['data'];
		}

		return false;
	}

	/**
	 * Process API report queue
	 *
	 * In local mode, this method returns early without processing.
	 * In community mode, it processes pending API reports.
	 *
	 * @param int $limit Maximum reports to process
	 * @return array|false Processing result or false if unavailable
	 */
	public function process_report_queue( $limit = 10 ) {
		$database = ReportedIP_Hive_Database::get_instance();

		$timeout_minutes = (int) get_option( 'reportedip_hive_processing_timeout_minutes', 10 );
		$recovery        = $database->recover_stuck_processing( $timeout_minutes );

		if ( ! $this->can_use_api() ) {
			return false;
		}

		if ( $this->is_rate_limited() ) {
			$this->logger->log_security_event(
				'queue_processing_skipped',
				'system',
				array( 'reason' => 'rate_limited' ),
				'low'
			);
			return array(
				'processed' => 0,
				'errors'    => 0,
				'total'     => 0,
				'skipped'   => true,
				'reason'    => 'rate_limited',
			);
		}

		$quota_status = $this->get_quota_status();
		if ( $quota_status['exhausted'] ) {
			$this->logger->log_security_event(
				'queue_processing_skipped',
				'system',
				array(
					'reason'     => $quota_status['reason'],
					'reset_time' => $quota_status['reset_time'],
					'message'    => $quota_status['message'],
				),
				'low'
			);
			return array(
				'processed'  => 0,
				'errors'     => 0,
				'total'      => 0,
				'skipped'    => true,
				'reason'     => $quota_status['reason'],
				'reset_time' => $quota_status['reset_time'],
			);
		}

		/*
		 * Cap the batch size by remaining quota — but only when the service
		 * actually exposes a finite cap. `remaining` is `-1` on unlimited
		 * tiers (Enterprise / Honeypot) and a `min( $limit, -1 )` would
		 * silently turn the batch into "process minus-one items" and trip
		 * the "no_quota" short-circuit below, leaving the queue stuck.
		 * Same shape as the 1.2.1 fix in has_report_quota().
		 */
		$effective_limit = $limit;
		if ( isset( $quota_status['remaining'] ) && $quota_status['remaining'] !== null && (int) $quota_status['remaining'] >= 0 ) {
			$effective_limit = min( $limit, (int) $quota_status['remaining'] );
		}

		if ( $effective_limit <= 0 ) {
			return array(
				'processed' => 0,
				'errors'    => 0,
				'total'     => 0,
				'skipped'   => true,
				'reason'    => 'no_quota',
			);
		}

		$pending_reports = $database->get_pending_api_reports( $effective_limit );

		$processed = 0;
		$errors    = 0;

		foreach ( $pending_reports as $report ) {
			try {
				$database->update_api_report_status( $report->id, 'processing' );
				$database->mark_report_submitted( $report->id );

				if ( $report->report_type === 'positive' ) {
					$result  = $this->report_positive_feedback( $report->ip_address, $report->comment ?? '' );
					$success = $result !== false;
				} else {
					$category_ids = explode( ',', $report->category_ids ?? '' );
					$result       = $this->report_ip( $report->ip_address, $category_ids, $report->comment ?? '' );
					$success      = isset( $result['success'] ) ? (bool) $result['success'] : false;
				}

				if ( $success ) {
					$database->update_api_report_status( $report->id, 'completed' );
					$database->update_daily_stats( 'api_reports_sent' );
					++$processed;
				} else {
					$error_message   = is_array( $result ) ? ( $result['message'] ?? 'Unknown error' ) : 'Unknown error';
					$is_rate_limited = is_array( $result ) && isset( $result['message'] ) &&
						( strpos( strtolower( $result['message'] ), 'rate limit' ) !== false ||
						strpos( strtolower( $result['message'] ), 'too many requests' ) !== false );

					if ( $is_rate_limited ) {
						$wpdb       = $GLOBALS['wpdb'];
						$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';
						// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Rate limit status update.
						$wpdb->update(
							$table_name,
							array(
								'status'        => 'pending',
								'error_message' => $error_message,
								'last_attempt'  => current_time( 'mysql' ),
							),
							array( 'id' => $report->id ),
							array( '%s', '%s', '%s' ),
							array( '%d' )
						);
						continue;
					} else {
						$database->update_api_report_status( $report->id, 'failed', $error_message );
						++$errors;
					}
				}
			} catch ( \Throwable $e ) {
				$database->update_api_report_status(
					$report->id,
					'failed',
					'Exception: ' . get_class( $e ) . ' — ' . $e->getMessage()
				);
				++$errors;
				continue;
			}

			usleep( 100000 );
		}

		return array(
			'processed' => $processed,
			'errors'    => $errors,
			'total'     => count( $pending_reports ),
			'recovered' => array(
				'reset'  => (int) ( $recovery['reset'] ?? 0 ),
				'failed' => (int) ( $recovery['failed'] ?? 0 ),
			),
		);
	}

	/**
	 * Send a 2FA mail via the reportedip.de relay endpoint.
	 *
	 * @param array $args {
	 *     Required: recipient. Optional: subject, body_text, body_html, headers, site_url.
	 * }
	 * @return array{ok: bool, queue_id?: int, status_code?: int, error?: string, retry_after?: int, remaining_quota?: array}
	 */
	public function relay_mail( array $args ) {
		$payload = array(
			'recipient' => (string) ( $args['recipient'] ?? '' ),
			'subject'   => (string) ( $args['subject'] ?? '' ),
			'body_text' => (string) ( $args['body_text'] ?? '' ),
			'body_html' => (string) ( $args['body_html'] ?? '' ),
			'headers'   => isset( $args['headers'] ) ? (array) $args['headers'] : array(),
			'site_url'  => (string) ( $args['site_url'] ?? home_url() ),
		);
		if ( ! empty( $args['reply_to'] ) && is_string( $args['reply_to'] ) ) {
			$payload['reply_to'] = $args['reply_to'];
		}
		return $this->relay_request( 'relay-mail', $payload );
	}

	/**
	 * Send a 2FA SMS via the reportedip.de relay endpoint.
	 *
	 * @param array $args {
	 *     Required: recipient_phone (E.164), message. Optional: site_url.
	 * }
	 * @return array{ok: bool, queue_id?: int, status_code?: int, error?: string, retry_after?: int, remaining_quota?: array}
	 */
	public function relay_sms( array $args ) {
		$payload = array(
			'recipient_phone' => (string) ( $args['recipient_phone'] ?? '' ),
			'site_url'        => (string) ( $args['site_url'] ?? home_url() ),
		);
		// Prefer client-only code transport (template + vars) so the actual verification
		// code never sits in a freshly-rendered string on the customer side.
		if ( ! empty( $args['template_code'] ) ) {
			$payload['template_code'] = (string) $args['template_code'];
			$payload['template_vars'] = isset( $args['template_vars'] ) ? (array) $args['template_vars'] : array();
		} else {
			$payload['message'] = (string) ( $args['message'] ?? '' );
		}
		return $this->relay_request( 'relay-sms', $payload );
	}

	/**
	 * Fetch the current monthly relay-usage and limits from the service.
	 *
	 * @param bool $force_refresh If true, bypass the 1-hour transient cache.
	 * @return array{tier?: string, role?: string, mail?: array, sms?: array, error?: string}
	 */
	public function get_relay_quota( $force_refresh = false ) {
		$cache_key = 'reportedip_hive_relay_quota';

		if ( ! $force_refresh ) {
			$cached = get_transient( $cache_key );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		$response = $this->make_request( 'GET', 'relay-quota', array(), null, $this->timeout );

		if ( is_wp_error( $response ) ) {
			return array( 'error' => $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( $code >= 200 && $code < 300 && is_array( $body ) ) {
			set_transient( $cache_key, $body, HOUR_IN_SECONDS );
			return $body;
		}

		return array(
			'error'        => 'http_' . $code,
			'status_code'  => $code,
			'response_raw' => is_array( $body ) ? $body : null,
		);
	}

	/**
	 * Internal helper for the two relay endpoints — POSTs JSON, parses the response,
	 * and translates HTTP 402/429 into structured results so callers can fall back gracefully.
	 *
	 * @param string $endpoint Slug under reportedip/v2/.
	 * @param array  $payload  Body to send.
	 * @return array
	 */
	private function relay_request( $endpoint, array $payload ) {
		$url = rtrim( $this->api_endpoint, '/' ) . '/' . ltrim( $endpoint, '/' );

		$args = array(
			'method'    => 'POST',
			'headers'   => array(
				'X-Key'        => $this->api_key,
				'Content-Type' => 'application/json',
				'Accept'       => 'application/json',
				'User-Agent'   => 'ReportedIP-Hive/' . REPORTEDIP_HIVE_VERSION,
			),
			'timeout'   => $this->timeout,
			'body'      => wp_json_encode( $payload ),
			'sslverify' => true,
		);

		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return array(
				'ok'        => false,
				'error'     => 'network: ' . $response->get_error_message(),
				'retryable' => true,
			);
		}

		$code  = (int) wp_remote_retrieve_response_code( $response );
		$json  = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$retry = (int) wp_remote_retrieve_header( $response, 'retry-after' );

		if ( $code >= 200 && $code < 300 ) {
			delete_transient( 'reportedip_hive_relay_quota' );
			return array(
				'ok'              => true,
				'status_code'     => $code,
				'queue_id'        => is_array( $json ) ? (int) ( $json['queue_id'] ?? 0 ) : 0,
				'remaining_quota' => is_array( $json ) ? ( $json['remaining_quota'] ?? null ) : null,
			);
		}

		if ( 402 === $code || 429 === $code ) {
			return array(
				'ok'           => false,
				'status_code'  => $code,
				'error'        => is_array( $json ) ? (string) ( $json['code'] ?? 'cap_or_backoff' ) : 'cap_or_backoff',
				'retry_after'  => $retry > 0 ? $retry : ( is_array( $json ) && isset( $json['data']['retry_after'] ) ? (int) $json['data']['retry_after'] : 0 ),
				'retryable'    => true,
				'soft_failure' => true,
			);
		}

		return array(
			'ok'          => false,
			'status_code' => $code,
			'error'       => is_array( $json ) ? (string) ( $json['code'] ?? 'http_' . $code ) : 'http_' . $code,
			'retryable'   => $code >= 500,
		);
	}

	/**
	 * Make HTTP request to API
	 */
	private function make_request( $method, $endpoint, $params = array(), $body = null, $timeout = null ) {
		$url = rtrim( $this->api_endpoint, '/' ) . '/' . ltrim( $endpoint, '/' );

		if ( ! empty( $params ) ) {
			$url .= '?' . http_build_query( $params );
		}

		$headers = array(
			'X-Key'      => $this->api_key,
			'User-Agent' => 'ReportedIP-Hive/' . REPORTEDIP_HIVE_VERSION . ' (WordPress/' . get_bloginfo( 'version' ) . ')',
			'Accept'     => 'application/json',
		);

		if ( strtoupper( $method ) === 'GET' ) {
			$etag_key    = 'reportedip_etag_' . md5( $url );
			$stored_etag = get_transient( $etag_key );
			if ( $stored_etag ) {
				$headers['If-None-Match'] = $stored_etag;
			}
		}

		$args = array(
			'method'     => strtoupper( $method ),
			'headers'    => $headers,
			'timeout'    => $timeout ?? $this->timeout,
			'user-agent' => 'ReportedIP-Hive/' . REPORTEDIP_HIVE_VERSION,
			'sslverify'  => true,
		);

		if ( $body !== null ) {
			if ( is_array( $body ) ) {
				$headers['Content-Type'] = 'application/x-www-form-urlencoded';
				$args['body']            = $body;
			} else {
				$args['body'] = $body;
			}
			$args['headers'] = $headers;
		}

		if ( defined( 'REPORTEDIP_DEBUG' ) && REPORTEDIP_DEBUG ) {
			$safe_url = preg_replace( '/([?&])(key|api_key|apikey)=[^&]+/', '$1$2=***REDACTED***', $url );
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Plugin diagnostic logging gated behind REPORTEDIP_DEBUG; debug.log only.
			error_log( "ReportedIP Hive API Request: $method $safe_url" );
			if ( $body ) {
				$safe_body = is_string( $body ) ? $body : wp_json_encode( $body );
				$safe_body = preg_replace( '/"(key|api_key|apikey)"\s*:\s*"[^"]*"/', '"$1":"***REDACTED***"', $safe_body );
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Plugin diagnostic logging gated behind REPORTEDIP_DEBUG; debug.log only.
				error_log( 'ReportedIP Hive API Body: ' . $safe_body );
			}
		}

		$response = wp_remote_request( $url, $args );

		if ( defined( 'REPORTEDIP_DEBUG' ) && REPORTEDIP_DEBUG && ! is_wp_error( $response ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Plugin diagnostic logging gated behind REPORTEDIP_DEBUG; debug.log only.
			error_log( 'ReportedIP Hive API Response: ' . wp_remote_retrieve_response_code( $response ) . ' ' . (string) ( wp_remote_retrieve_body( $response ) ?? '' ) );
		}

		if ( ! is_wp_error( $response ) && strtoupper( $method ) === 'GET' ) {
			$status_code = wp_remote_retrieve_response_code( $response );
			$etag_key    = 'reportedip_etag_' . md5( $url );

			if ( $status_code === 304 ) {
				$cached_body = get_transient( $etag_key . '_body' );
				if ( $cached_body ) {
					$response['body']             = $cached_body;
					$response['response']['code'] = 200;
				}
			} else {
				$response_etag = wp_remote_retrieve_header( $response, 'etag' );
				if ( $response_etag ) {
					set_transient( $etag_key, $response_etag, HOUR_IN_SECONDS );
					$response_body = wp_remote_retrieve_body( $response );
					set_transient( $etag_key . '_body', $response_body, HOUR_IN_SECONDS );
				}
			}
		}

		return $response;
	}

	/**
	 * Verify API key with the service
	 *
	 * @param string|null $api_key Optional API key to verify. Uses configured key if not provided.
	 * @return array|false Array with 'valid' key on success, false on failure
	 */
	public function verify_api_key( $api_key = null ) {
		$original_key = $this->api_key;

		if ( $api_key !== null ) {
			$this->api_key = $api_key;
		}

		if ( empty( $this->api_key ) ) {
			$this->api_key = $original_key;
			return array(
				'valid'   => false,
				'message' => 'No API key provided',
			);
		}

		$response = $this->make_request( 'GET', 'verify-key' );

		$this->api_key = $original_key;

		if ( is_wp_error( $response ) ) {
			return array(
				'valid'   => false,
				'message' => $response->get_error_message(),
			);
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		$body          = wp_remote_retrieve_body( $response );
		$data          = json_decode( $body, true );

		if ( $response_code === 200 && isset( $data['data']['valid'] ) ) {
			$limits = $data['data']['limits'] ?? array();
			return array(
				'valid'             => (bool) $data['data']['valid'],
				'keyName'           => $data['data']['keyName'] ?? '',
				'userRole'          => $data['data']['userRole'] ?? '',
				'isHoneypotKey'     => ! empty( $data['data']['isHoneypotKey'] ),
				'limits'            => $limits,
				'remainingApiCalls' => $limits['remainingApiCalls'] ?? 0,
				'dailyApiLimit'     => $limits['dailyApiLimit'] ?? 0,
				'remainingReports'  => $limits['remainingReports'] ?? 0,
				'dailyReportLimit'  => $limits['dailyReportLimit'] ?? 0,
				'dailyReportUsage'  => $limits['dailyReportUsage'] ?? 0,
				'resetTime'         => $limits['resetTime'] ?? null,
			);
		}

		return array(
			'valid'   => false,
			'message' => 'Invalid response from server',
		);
	}

	/**
	 * Set API key (for temporary use during verification)
	 *
	 * @param string $api_key The API key to set
	 */
	public function set_api_key( $api_key ) {
		$this->api_key = $api_key;
	}

	/**
	 * Get API status including remaining credits
	 *
	 * @return array|false API status array or false on failure
	 */
	public function get_api_status() {
		if ( ! $this->is_configured() ) {
			return false;
		}

		$cached_status = get_transient( 'reportedip_hive_api_status' );
		if ( $cached_status !== false ) {
			return $cached_status;
		}

		$result = $this->verify_api_key();

		if ( $result && isset( $result['valid'] ) && $result['valid'] ) {
			$status = array(
				'valid'             => true,
				'remainingApiCalls' => $result['remainingApiCalls'] ?? 0,
				'dailyApiLimit'     => $result['dailyApiLimit'] ?? 0,
				'keyName'           => $result['keyName'] ?? '',
				'userRole'          => $result['userRole'] ?? '',
			);

			$this->persist_api_status( $status );

			return $status;
		}

		return false;
	}

	/**
	 * Persist the verified API status and emit the tier-changed action when the role flipped.
	 *
	 * @param array $status Validated status payload to cache.
	 * @return void
	 * @since 1.5.3
	 */
	private function persist_api_status( $status ) {
		$previous  = get_transient( 'reportedip_hive_api_status' );
		$prev_tier = 'free';
		if ( is_array( $previous ) && ! empty( $previous['userRole'] ) ) {
			$prev_tier = ReportedIP_Hive_Mode_Manager::tier_from_role( (string) $previous['userRole'] );
		}

		set_transient( 'reportedip_hive_api_status', $status, 5 * MINUTE_IN_SECONDS );

		$new_role = (string) ( $status['userRole'] ?? '' );
		$new_tier = $new_role !== '' ? ReportedIP_Hive_Mode_Manager::tier_from_role( $new_role ) : 'free';

		if ( $prev_tier !== $new_tier ) {
			delete_transient( 'reportedip_hive_relay_quota' );
			do_action( 'reportedip_hive_tier_changed', $prev_tier, $new_tier );
		}
	}

	/**
	 * Refresh API quota from server
	 * Should be called every 6 hours via cron
	 *
	 * @return array|false Quota data or false on failure
	 */
	public function refresh_api_quota() {
		if ( ! $this->is_configured() ) {
			return false;
		}

		$result = $this->verify_api_key();

		if ( $result && isset( $result['valid'] ) && $result['valid'] ) {
			$quota_data = array(
				'remaining_api_calls' => $result['remainingApiCalls'] ?? 0,
				'daily_api_limit'     => $result['dailyApiLimit'] ?? 0,
				'remaining_reports'   => $result['remainingReports'] ?? 0,
				'daily_report_limit'  => $result['dailyReportLimit'] ?? 0,
				'daily_report_usage'  => $result['dailyReportUsage'] ?? 0,
				'reset_time'          => $result['resetTime'] ?? null,
				'user_role'           => $result['userRole'] ?? '',
				'is_honeypot'         => ! empty( $result['isHoneypotKey'] ),
				'fetched_at'          => current_time( 'mysql' ),
			);

			set_transient( 'reportedip_hive_api_quota', $quota_data, 6 * HOUR_IN_SECONDS );

			$this->persist_api_status(
				array(
					'valid'             => true,
					'remainingApiCalls' => $result['remainingApiCalls'] ?? 0,
					'dailyApiLimit'     => $result['dailyApiLimit'] ?? 0,
					'keyName'           => $result['keyName'] ?? '',
					'userRole'          => $result['userRole'] ?? '',
				)
			);

			$this->logger->log_security_event(
				'api_quota_refreshed',
				'system',
				$quota_data,
				'low'
			);

			return $quota_data;
		}

		return false;
	}

	/**
	 * Get cached API quota
	 *
	 * @return array|false Quota data or false if not cached
	 */
	public function get_cached_quota() {
		return get_transient( 'reportedip_hive_api_quota' );
	}

	/**
	 * Check if we have report quota available
	 *
	 * @return bool True if reports can be sent
	 */
	public function has_report_quota() {
		if ( $this->is_rate_limited() ) {
			return false;
		}

		$quota = $this->get_cached_quota();

		if ( ! $quota ) {
			return true;
		}

		$limit = isset( $quota['daily_report_limit'] ) ? (int) $quota['daily_report_limit'] : null;

		if ( 0 === $limit ) {
			return false;
		}

		if ( null !== $limit && $limit > 0 && isset( $quota['remaining_reports'] ) && (int) $quota['remaining_reports'] <= 0 ) {
			return false;
		}

		return true;
	}

	/**
	 * Get quota status with detailed information
	 *
	 * @return array Status with reason and messages
	 */
	public function get_quota_status() {
		$quota = $this->get_cached_quota();

		if ( ! $quota ) {
			return array(
				'exhausted'  => false,
				'reason'     => 'unknown',
				'reset_time' => null,
				'remaining'  => null,
				'limit'      => null,
				'user_role'  => 'unknown',
				'message'    => __( 'Quota status unknown - will attempt API calls', 'reportedip-hive' ),
			);
		}

		$report_limit = isset( $quota['daily_report_limit'] ) ? (int) $quota['daily_report_limit'] : null;

		if ( $report_limit === 0 ) {
			return array(
				'exhausted'  => true,
				'reason'     => 'no_permission',
				'reset_time' => null,
				'remaining'  => 0,
				'limit'      => 0,
				'user_role'  => $quota['user_role'] ?? 'free',
				'message'    => __( 'Your API key currently has no report permission. Please check your account status or upgrade to Contributor.', 'reportedip-hive' ),
			);
		}

		if ( $report_limit !== null && $report_limit > 0 && isset( $quota['remaining_reports'] ) && (int) $quota['remaining_reports'] <= 0 ) {
			$reset_time_formatted = '00:00';
			if ( ! empty( $quota['reset_time'] ) ) {
				$reset_timestamp      = strtotime( $quota['reset_time'] );
				$reset_time_formatted = $reset_timestamp ? wp_date( 'H:i', $reset_timestamp ) : '00:00';
			}

			return array(
				'exhausted'  => true,
				'reason'     => 'daily_limit',
				'reset_time' => $quota['reset_time'] ?? null,
				'remaining'  => 0,
				'limit'      => $quota['daily_report_limit'] ?? 0,
				'usage'      => $quota['daily_report_usage'] ?? 0,
				'user_role'  => $quota['user_role'] ?? '',
				'message'    => sprintf(
					/* translators: 1: current usage, 2: daily limit, 3: reset time */
					__( 'Daily report limit reached (%1$d/%2$d). Resets at %3$s UTC.', 'reportedip-hive' ),
					$quota['daily_report_usage'] ?? 0,
					$quota['daily_report_limit'] ?? 0,
					$reset_time_formatted
				),
			);
		}

		return array(
			'exhausted'  => false,
			'reason'     => null,
			'reset_time' => $quota['reset_time'] ?? null,
			'remaining'  => $quota['remaining_reports'] ?? 0,
			'limit'      => $quota['daily_report_limit'] ?? 0,
			'usage'      => $quota['daily_report_usage'] ?? 0,
			'user_role'  => $quota['user_role'] ?? '',
			'message'    => sprintf(
				/* translators: %d: remaining reports */
				__( '%d reports remaining today.', 'reportedip-hive' ),
				$quota['remaining_reports'] ?? 0
			),
		);
	}

	/**
	 * Decrement local quota counter after successful report
	 */
	private function decrement_quota_counter() {
		$quota = $this->get_cached_quota();

		if ( $quota && isset( $quota['remaining_reports'] ) ) {
			$quota['remaining_reports']  = max( 0, $quota['remaining_reports'] - 1 );
			$quota['daily_report_usage'] = ( $quota['daily_report_usage'] ?? 0 ) + 1;

			set_transient( 'reportedip_hive_api_quota', $quota, 6 * HOUR_IN_SECONDS );
		}
	}

	/**
	 * Check if we're currently rate limited (server-side or client-side)
	 */
	public function is_rate_limited() {
		$rate_limit_reset = get_transient( 'reportedip_hive_rate_limit_reset' );
		if ( $rate_limit_reset && $rate_limit_reset > time() ) {
			return true;
		}

		if ( $this->is_local_rate_limited() ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if we've exceeded local rate limit
	 */
	private function is_local_rate_limited() {
		$max_calls     = get_option( 'reportedip_hive_max_api_calls_per_hour', 100 );
		$current_calls = $this->get_hourly_api_call_count();

		return $current_calls >= $max_calls;
	}

	/**
	 * Get current hourly API call count
	 */
	public function get_hourly_api_call_count() {
		return (int) get_transient( 'reportedip_hive_hourly_api_calls' ) ?: 0;
	}

	/**
	 * Increment hourly API call count
	 */
	private function increment_hourly_api_calls() {
		$current_calls = $this->get_hourly_api_call_count();
		++$current_calls;

		set_transient( 'reportedip_hive_hourly_api_calls', $current_calls, HOUR_IN_SECONDS );

		return $current_calls;
	}

	/**
	 * Set rate limit status
	 */
	public function set_rate_limited( $reset_time ) {
		set_transient( 'reportedip_hive_rate_limit_reset', $reset_time, $reset_time - time() );
	}

	/**
	 * Track API call for monitoring
	 */
	private function track_api_call( $success, $response_time, $error_type = null ) {
		$this->increment_hourly_api_calls();

		$stats = get_option(
			'reportedip_hive_api_stats',
			array(
				'total_calls'         => 0,
				'successful_calls'    => 0,
				'failed_calls'        => 0,
				'total_response_time' => 0,
				'last_reset'          => current_time( 'mysql' ),
				'error_types'         => array(),
			)
		);

		++$stats['total_calls'];
		$stats['total_response_time'] += $response_time;

		if ( $success ) {
			++$stats['successful_calls'];
		} else {
			++$stats['failed_calls'];

			if ( $error_type ) {
				if ( ! isset( $stats['error_types'][ $error_type ] ) ) {
					$stats['error_types'][ $error_type ] = 0;
				}
				++$stats['error_types'][ $error_type ];
			}
		}

		$stats['success_rate']      = $stats['total_calls'] > 0 ?
			round( ( $stats['successful_calls'] / $stats['total_calls'] ) * 100, 2 ) : 0;
		$stats['avg_response_time'] = $stats['total_calls'] > 0 ?
			round( $stats['total_response_time'] / $stats['total_calls'], 2 ) : 0;

		update_option( 'reportedip_hive_api_stats', $stats );

		if ( ! $success && $error_type !== 'rate_limited' ) {
			$this->logger->log_security_event(
				'api_call_failed',
				'system',
				array(
					'error_type'    => $error_type,
					'response_time' => $response_time,
					'success_rate'  => $stats['success_rate'],
				),
				'medium'
			);
		}

		if ( $stats['total_calls'] >= 10 && $stats['success_rate'] < 80 ) {
			$last_health_warning = get_transient( 'reportedip_hive_health_warning_logged' );

			if ( ! $last_health_warning ) {
				$this->logger->log_security_event(
					'api_health_degraded',
					'system',
					array(
						'success_rate' => $stats['success_rate'],
						'total_calls'  => $stats['total_calls'],
						'failed_calls' => $stats['failed_calls'],
					),
					'high'
				);

				set_transient( 'reportedip_hive_health_warning_logged', time(), HOUR_IN_SECONDS );
			}
		}
	}

	/**
	 * Get comprehensive API health status
	 */
	public function get_api_health_status() {
		$api_stats = get_option(
			'reportedip_hive_api_stats',
			array(
				'total_calls'       => 0,
				'successful_calls'  => 0,
				'failed_calls'      => 0,
				'success_rate'      => 0,
				'avg_response_time' => 0,
			)
		);

		$cache_stats   = $this->cache->get_cache_statistics();
		$cache_savings = $this->cache->estimate_monthly_savings();

		return array(
			'api_configured'    => $this->is_configured(),
			'rate_limited'      => $this->is_rate_limited(),
			'api_stats'         => $api_stats,
			'cache_stats'       => $cache_stats,
			'estimated_savings' => $cache_savings,
			'health_score'      => $this->calculate_health_score( $api_stats, $cache_stats ),
		);
	}
	/**
	 * Calculate overall health score
	 */
	private function calculate_health_score( $api_stats, $cache_stats ) {
		$score = 0;

		if ( $this->is_configured() ) {
			$score += 30;
		}

		if ( isset( $api_stats['success_rate'] ) && $api_stats['total_calls'] > 0 ) {
			$score += ( $api_stats['success_rate'] / 100 ) * 30;
		} elseif ( $this->is_configured() ) {
			$score += 15;
		}

		if ( get_option( 'reportedip_hive_enable_caching', true ) ) {
			if ( isset( $cache_stats['hit_rate'] ) && $cache_stats['total_requests'] > 0 ) {
				$score += ( $cache_stats['hit_rate'] / 100 ) * 25;
			} else {
				$score += 12;
			}
		} else {
			$score += 25;
		}

		if ( isset( $api_stats['avg_response_time'] ) && $api_stats['total_calls'] > 0 ) {
			$response_score = max( 0, 100 - ( $api_stats['avg_response_time'] / 10 ) );
			$score         += ( $response_score / 100 ) * 15;
		} elseif ( $this->is_configured() ) {
			$score += 7;
		}

		return round( $score, 1 );
	}


	/**
	 * Get estimated monthly API usage
	 */
	public function estimate_monthly_usage() {
		$api_stats = get_option( 'reportedip_hive_api_stats', array() );

		if ( empty( $api_stats ) || ! isset( $api_stats['last_reset'] ) ) {
			return array(
				'estimated_monthly_calls' => 0,
				'current_daily_average'   => 0,
				'confidence'              => 'low',
			);
		}

		$days_since_reset = max( 1, ( time() - strtotime( $api_stats['last_reset'] ) ) / 86400 );
		$daily_average    = $api_stats['total_calls'] / $days_since_reset;
		$monthly_estimate = $daily_average * 30;

		$confidence = 'low';
		if ( $days_since_reset >= 7 ) {
			$confidence = 'medium';
		}
		if ( $days_since_reset >= 30 ) {
			$confidence = 'high';
		}

		return array(
			'estimated_monthly_calls' => round( $monthly_estimate ),
			'current_daily_average'   => round( $daily_average, 1 ),
			'confidence'              => $confidence,
			'days_of_data'            => round( $days_since_reset, 1 ),
		);
	}
}
