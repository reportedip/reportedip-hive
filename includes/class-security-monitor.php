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

	/**
	 * Default category-id mapping per security event type.
	 *
	 * The service-side taxonomy in `wp_reportedip_threat_categories` covers
	 * both AbuseIPDB-style legacy categories (1–30: 4 DDoS, 12 Blog Spam,
	 * 15 Hacking, 18 Brute-Force, 21 Web App Attack, 22 SSH, …) and a
	 * WordPress-specific extension range (31+: 31 WP Login Brute Force,
	 * 33 WP XML-RPC Brute Force, 34 WP REST API Abuse, 39 WP Comment Spam,
	 * 55 WP User Enumeration, 56 WP Version Scanning, 57 WP Plugin Scanning,
	 * 58 WP Config Exposure, …). The mapping below favours the WP-specific
	 * IDs for the new 1.2.0 sensors so confidence scoring on the service
	 * side aggregates them correctly; legacy event types keep their original
	 * IDs to preserve behaviour for existing 1.x deployments.
	 *
	 * Per-site overrides via the `reportedip_hive_event_category_map`
	 * filter; unknown IDs (not present in the cached service category
	 * list) are filtered out by `get_validated_category_mapping()`.
	 */
	private static $default_category_mapping = array(
		'failed_login'       => array( 18 ),
		'comment_spam'       => array( 12 ),
		'xmlrpc_abuse'       => array( 21 ),
		'admin_scanning'     => array( 21, 15 ),
		'reputation_threat'  => array( 15, 4 ),
		'user_enumeration'   => array( 55 ),
		'rest_abuse'         => array( 34 ),
		'app_password_abuse' => array( 31, 18 ),
		'password_spray'     => array( 31, 18 ),
		'scan_404'           => array( 57, 56, 58 ),
		'wc_login_failed'    => array( 31 ),
		'geo_anomaly'        => array( 15 ),
		'2fa_brute_force'    => array( 31, 18 ),
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
	 * Check failed login threshold.
	 *
	 * Runs two layered checks:
	 *  1. Per-IP failed-login count vs. configured threshold.
	 *  2. Distinct-username password-spray check — fires before the per-IP
	 *     count threshold when an IP probes many different usernames in a
	 *     short window, which is a stronger credential-stuffing indicator.
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

		$this->record_username_for_spray_detection( $ip_address, $username );

		$this->database->track_attempt( $ip_address, 'login', $track_username, $track_user_agent );

		if ( $this->check_password_spray_threshold( $ip_address ) ) {
			return true;
		}

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
	 * Record a hashed username sample for the password-spray detector.
	 *
	 * We never persist plaintext usernames here — only a salted hash, just
	 * enough to count distinct values without leaking PII. The transient is
	 * IP-scoped and TTL-bound, so no cleanup pass is needed.
	 */
	private function record_username_for_spray_detection( $ip_address, $username ) {
		if ( '' === (string) $username ) {
			return;
		}

		$timeframe = (int) get_option( 'reportedip_hive_password_spray_timeframe', 10 );
		$timeframe = max( 1, $timeframe );

		$key = 'rip_spray_' . md5( $ip_address );
		/** @var array<string,int>|false $bucket */
		$bucket = get_transient( $key );
		if ( ! is_array( $bucket ) ) {
			$bucket = array();
		}

		$hash            = substr( hash( 'sha256', strtolower( $username ) . wp_salt() ), 0, 16 );
		$bucket[ $hash ] = time();

		$cutoff = time() - ( $timeframe * MINUTE_IN_SECONDS );
		foreach ( $bucket as $h => $t ) {
			if ( $t < $cutoff ) {
				unset( $bucket[ $h ] );
			}
		}

		set_transient( $key, $bucket, $timeframe * MINUTE_IN_SECONDS );
	}

	/**
	 * Distinct-username threshold check — fires when the IP has tried a
	 * configurable number of unique usernames within the spray timeframe.
	 *
	 * @return bool True if the threshold fired.
	 */
	private function check_password_spray_threshold( $ip_address ) {
		$threshold = (int) get_option( 'reportedip_hive_password_spray_threshold', 5 );
		$timeframe = (int) get_option( 'reportedip_hive_password_spray_timeframe', 10 );
		$threshold = max( 2, $threshold );
		$timeframe = max( 1, $timeframe );

		$key    = 'rip_spray_' . md5( $ip_address );
		$bucket = get_transient( $key );
		if ( ! is_array( $bucket ) ) {
			return false;
		}

		$cutoff = time() - ( $timeframe * MINUTE_IN_SECONDS );
		$count  = 0;
		foreach ( $bucket as $t ) {
			if ( $t >= $cutoff ) {
				++$count;
			}
		}

		if ( $count < $threshold ) {
			return false;
		}

		if ( $this->database->is_blocked( $ip_address ) ) {
			return true;
		}

		$this->handle_threshold_exceeded(
			$ip_address,
			'password_spray',
			array(
				'attempts'  => $count,
				'threshold' => $threshold,
				'timeframe' => $timeframe,
			)
		);

		delete_transient( $key );

		return true;
	}

	/**
	 * Generic threshold tracker for the auxiliary sensors (user-enumeration,
	 * REST abuse, 404-scanning, app-password abuse, WooCommerce-login).
	 *
	 * Records an attempt of $attempt_type, runs the windowed counter, and
	 * fires {@see handle_threshold_exceeded()} once the threshold is hit.
	 * Every sensor uses the same shape so they all look identical in the
	 * logs and queue, which simplifies dashboarding.
	 *
	 * @param string $ip_address   Client IP.
	 * @param string $attempt_type Attempt-type slug stored in the attempts table.
	 * @param string $event_type   Event-type slug used by category mapping / comments.
	 * @param int    $threshold    Min attempts to fire (must be ≥ 1).
	 * @param int    $timeframe    Counting window in minutes.
	 * @param array  $extra        Optional extra payload merged into the threshold details.
	 * @return bool                True if the threshold fired.
	 */
	public function track_generic_attempt( $ip_address, $attempt_type, $event_type, $threshold, $timeframe, array $extra = array() ) {
		if ( '' === (string) $ip_address || 'unknown' === $ip_address ) {
			return false;
		}

		if ( $this->database->is_whitelisted( $ip_address ) ) {
			return false;
		}

		$track_user_agent = null;
		if ( get_option( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$track_user_agent = ! empty( $user_agent ) ? substr( (string) $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH ) : '';
		}

		$this->database->track_attempt( $ip_address, $attempt_type, null, $track_user_agent );

		$threshold = max( 1, (int) $threshold );
		$timeframe = max( 1, (int) $timeframe );
		$count     = $this->database->get_attempt_count( $ip_address, $attempt_type, $timeframe );

		if ( $count < $threshold ) {
			return false;
		}

		if ( $this->database->is_blocked( $ip_address ) ) {
			return true;
		}

		$details = array_merge(
			array(
				'attempts'  => $count,
				'threshold' => $threshold,
				'timeframe' => $timeframe,
			),
			$extra
		);

		$this->handle_threshold_exceeded( $ip_address, $event_type, $details );

		return true;
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
	 * Dispatch the post-trip pipeline: log, stats, auto-block, API report, admin email.
	 *
	 * Public so sensors that maintain their own counter (e.g. the 2FA per-IP
	 * transient throttle) can invoke the same consequences as sensors that
	 * funnel through `track_generic_attempt()`.
	 *
	 * @param string $ip_address Client IP.
	 * @param string $event_type Event slug — must exist in the category and stat mapping tables, otherwise the report rolls up to fallback buckets.
	 * @param array  $details    Event metadata, written to logs and the report comment verbatim.
	 * @return void
	 * @since  1.0.0
	 */
	public function handle_threshold_exceeded( $ip_address, $event_type, $details ) {
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

		$reason = $this->get_block_reason( $event_type, $details );

		$use_ladder = class_exists( 'ReportedIP_Hive_Block_Escalation' )
			&& ReportedIP_Hive_Block_Escalation::is_enabled();

		if ( $use_ladder ) {
			$duration_minutes = ReportedIP_Hive_Block_Escalation::next_block_minutes( $ip_address );
			$duration_hours   = (int) ceil( $duration_minutes / 60 );
		} else {
			$duration_hours   = (int) get_option( 'reportedip_hive_block_duration', 24 );
			$duration_minutes = $duration_hours * 60;
		}

		$this->logger->log_security_event(
			'attempting_auto_block',
			$ip_address,
			array(
				'event_type'         => $event_type,
				'reason'             => $reason,
				'duration_minutes'   => $duration_minutes,
				'duration_hours'     => $duration_hours,
				'escalation_enabled' => $use_ladder,
				'threshold_details'  => $details,
			),
			'high'
		);

		$result = $use_ladder
			? $this->database->block_ip_for_minutes( $ip_address, $reason, 'automatic', $duration_minutes )
			: $this->database->block_ip( $ip_address, $reason, 'automatic', $duration_hours );

		if ( $result ) {
			$client = ReportedIP_Hive::get_instance();
			$client->mark_ip_blocked( $ip_address );

			$cache_key = 'rip_access_' . md5( $ip_address );
			wp_cache_delete( $cache_key, 'reportedip' );

			$this->logger->log_security_event(
				'ip_blocked',
				$ip_address,
				array(
					'reason'           => $reason,
					'duration_minutes' => $duration_minutes,
					'duration_hours'   => $duration_hours,
					'trigger_event'    => $event_type,
					'block_type'       => 'automatic',
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
	 * Get category IDs for event type.
	 *
	 * Default seed mapping in self::$default_category_mapping; per-site overrides
	 * via the `reportedip_hive_event_category_map` filter; IDs not found in the
	 * cached service-side category list are filtered out via
	 * get_validated_category_mapping(). Falls back to category 15 (Hacking) when
	 * the event type is unknown — keeps reports flowing for new sensors that
	 * forgot to add a mapping.
	 *
	 * @param string $event_type Event-type slug (e.g. failed_login).
	 * @return int[]             Category-id list to send to the service API.
	 */
	public function get_category_ids_for_event( $event_type ) {
		$category_mapping = self::$default_category_mapping;

		$category_mapping = (array) apply_filters( 'reportedip_hive_event_category_map', $category_mapping );

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

			case 'user_enumeration':
				return sprintf(
					'WordPress user enumeration detected on %s (%s): %d probes in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'rest_abuse':
				return sprintf(
					'WordPress REST API abuse detected on %s (%s): %d requests in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'app_password_abuse':
				return sprintf(
					'WordPress application-password abuse detected on %s (%s): %d failed authentications in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'password_spray':
				return sprintf(
					'WordPress password-spray attack detected on %s (%s): %d distinct usernames probed in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'scan_404':
				return sprintf(
					'WordPress 404-scanning detected on %s (%s): %d requests on suspicious paths in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'wc_login_failed':
				return sprintf(
					'WooCommerce login brute-force detected on %s (%s): %d failed attempts in %d minutes',
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

			case 'user_enumeration':
				return sprintf( 'User enumeration: %d probes in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'rest_abuse':
				return sprintf( 'REST API abuse: %d requests in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'app_password_abuse':
				return sprintf( 'Application-password abuse: %d failed auths in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'password_spray':
				return sprintf( 'Password spray: %d usernames in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'scan_404':
				return sprintf( '404 scanner: %d requests in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'wc_login_failed':
				return sprintf( 'WooCommerce login attempts: %d in %d minutes', $details['attempts'], $details['timeframe'] );

			default:
				return 'Suspicious activity detected';
		}
	}

	/**
	 * Get stat type for event.
	 *
	 * The stats table has a fixed set of counters (see
	 * ReportedIP_Hive_Database::update_daily_stats whitelist), so new sensors
	 * roll up into the closest existing counter:
	 *   - login-shaped attacks → failed_logins
	 *   - reconnaissance / scan attacks → blocked_ips
	 *   - everything else → failed_logins (safe default)
	 */
	private function get_stat_type_for_event( $event_type ) {
		$stat_mapping = array(
			'failed_login'       => 'failed_logins',
			'comment_spam'       => 'comment_spam',
			'xmlrpc_abuse'       => 'xmlrpc_calls',
			'admin_scanning'     => 'failed_logins',
			'password_spray'     => 'failed_logins',
			'app_password_abuse' => 'failed_logins',
			'wc_login_failed'    => 'failed_logins',
			'user_enumeration'   => 'blocked_ips',
			'rest_abuse'         => 'blocked_ips',
			'scan_404'           => 'blocked_ips',
			'2fa_brute_force'    => 'failed_logins',
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

		$recipients = ReportedIP_Hive_Defaults::notify_recipients();
		if ( empty( $recipients ) ) {
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
				'to'              => implode( ', ', $recipients ),
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
