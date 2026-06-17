<?php
/**
 * Security Monitor Class for ReportedIP Hive.
 *
 * Detects security events (failed logins, comment spam, XMLRPC abuse,
 * admin scanning) and feeds them into the local IP-Manager and the
 * community-mode reporting queue.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
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
		'failed_login'        => array( 18 ),
		'comment_spam'        => array( 12 ),
		'xmlrpc_abuse'        => array( 21 ),
		'admin_scanning'      => array( 21, 15 ),
		'reputation_threat'   => array( 15, 4 ),
		'user_enumeration'    => array( 55 ),
		'rest_abuse'          => array( 34 ),
		'app_password_abuse'  => array( 31, 18 ),
		'password_spray'      => array( 31, 18 ),
		'scan_404'            => array( 57, 56, 58 ),
		'wc_login_failed'     => array( 31 ),
		'geo_anomaly'         => array( 15 ),
		'2fa_brute_force'     => array( 31, 18 ),
		'decoy_pathblock_hit' => array( 21, 15 ),
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
		$threshold = ReportedIP_Hive_Hardening_Mode::effective_failed_login_threshold(
			(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold', 5 )
		);
		$timeframe = ReportedIP_Hive_Hardening_Mode::effective_failed_login_timeframe(
			(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_timeframe', 15 )
		);

		$track_username   = null;
		$track_user_agent = null;

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
			$track_username = $username;
		}

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$track_user_agent = ! empty( $user_agent ) ? substr( (string) $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH ) : '';
		}

		$this->record_username_for_spray_detection( $ip_address, $username );

		$this->database->track_attempt( $ip_address, 'login', $track_username, $track_user_agent );

		$this->maybe_check_coordinated_realtime();

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

			if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
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

		$timeframe = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_spray_timeframe', 10 );
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
		$threshold = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_spray_threshold', 5 );
		$timeframe = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_password_spray_timeframe', 10 );
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
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ) {
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
		$threshold = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_threshold', 3 );
		$timeframe = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_spam_timeframe', 60 );

		$track_user_agent = null;
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ) {
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
		$threshold = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_xmlrpc_threshold', 10 );
		$timeframe = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_xmlrpc_timeframe', 60 );

		$track_user_agent = null;
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ) {
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

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_block', true ) ) {
			$this->auto_block_ip( $ip_address, $event_type, $details );
		}

		$this->report_security_event( $ip_address, $event_type, $details );

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_admin', true ) ) {
			$this->send_admin_notification( $ip_address, $event_type, $details );
		}
	}

	/**
	 * Auto-block IP address
	 */
	public function auto_block_ip( $ip_address, $event_type, $details ) {
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ) {
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
			$duration_hours   = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_duration', 24 );
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
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ) {
			$report_details['report_only_mode']   = true;
			$report_details['would_have_blocked'] = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_block', true );
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
					'report_only_mode' => ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ),
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
					'report_only_mode' => ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ),
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
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ) {
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

		$cooldown_minutes = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notification_cooldown_minutes', 60 );
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

		$event_type_safe = $event_type ?? 'unknown';

		$burst_summary = $this->reserve_event_burst_slot( $event_type_safe, $ip_address, $details );
		if ( null === $burst_summary ) {
			return;
		}

		set_transient( $transient_key, true, $cooldown_minutes * MINUTE_IN_SECONDS );

		$recipients = ReportedIP_Hive_Defaults::notify_recipients();
		if ( empty( $recipients ) ) {
			return;
		}

		$site_name = wp_specialchars_decode( (string) ( get_bloginfo( 'name' ) ?: 'WordPress Site' ), ENT_QUOTES );

		$event_label = ucwords( str_replace( '_', ' ', $event_type_safe ) );
		$subject     = sprintf( '[%s] Security Alert: %s', $site_name, $event_label );
		if ( $burst_summary['suppressed_count'] > 0 ) {
			$subject .= sprintf( ' (+%d)', (int) $burst_summary['suppressed_count'] );
		}
		$timestamp = current_time( 'Y-m-d H:i:s' );

		$blocks = $this->build_alert_blocks( $event_label, $ip_address, $details, $timestamp, $burst_summary );

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
	 * Per-event-type burst-cap with suppression accounting.
	 *
	 * The legacy `rip_notif_<ip+event>`-cooldown is per-IP, so a distributed
	 * attack (different IPs trigger the same event type within seconds) used
	 * to send one mail per IP — the relay throttles them, the fallback drops
	 * them into wp_mail(), the admin still drowns. This second gate caps the
	 * total mail volume per event_type and remembers how many alerts were
	 * suppressed so the next outgoing mail can carry a digest line.
	 *
	 * Returns null when the slot is closed (callers must NOT send a mail);
	 * otherwise an array describing the suppression window since the last
	 * delivery, suitable for embedding in the alert body.
	 *
	 * @param string $event_type Event slug.
	 * @param string $ip_address Triggering IP (recorded in the suppression bucket).
	 * @param array  $details    Threshold details (for the bucket).
	 * @return array{suppressed_count:int,unique_ips:int,since:string,sample_ips:string[]}|null
	 * @since  2.0.6
	 */
	private function reserve_event_burst_slot( string $event_type, string $ip_address, array $details ) {
		$cap_minutes = (int) ReportedIP_Hive_Option_Routing::get(
			'reportedip_hive_notify_event_cap_minutes',
			15
		);
		$cap_minutes = max( 0, $cap_minutes );

		if ( 0 === $cap_minutes ) {
			return array(
				'suppressed_count' => 0,
				'unique_ips'       => 0,
				'since'            => '',
				'sample_ips'       => array(),
			);
		}

		$bucket_key = 'rip_notif_event_' . md5( $event_type );
		$bucket     = get_transient( $bucket_key );
		$now        = time();

		if ( is_array( $bucket ) && isset( $bucket['next_allowed_at'] ) && $bucket['next_allowed_at'] > $now ) {
			$bucket['suppressed_count']              = (int) ( $bucket['suppressed_count'] ?? 0 ) + 1;
			$bucket['unique_ips_map']                = isset( $bucket['unique_ips_map'] ) && is_array( $bucket['unique_ips_map'] )
				? $bucket['unique_ips_map']
				: array();
			$bucket['unique_ips_map'][ $ip_address ] = ( $bucket['unique_ips_map'][ $ip_address ] ?? 0 ) + 1;
			if ( count( $bucket['unique_ips_map'] ) > 50 ) {
				$bucket['unique_ips_map'] = array_slice( $bucket['unique_ips_map'], -50, null, true );
			}
			if ( empty( $bucket['first_suppressed_at'] ) ) {
				$bucket['first_suppressed_at'] = $now;
			}

			set_transient( $bucket_key, $bucket, max( 60, $bucket['next_allowed_at'] - $now ) );

			$this->logger->log_security_event(
				'notification_event_cap_suppressed',
				$ip_address,
				array(
					'event_type'       => $event_type,
					'cap_minutes'      => $cap_minutes,
					'suppressed_count' => (int) $bucket['suppressed_count'],
					'unique_ips'       => count( $bucket['unique_ips_map'] ),
					'details'          => $details,
					'reason'           => 'Per-event-type burst cap active; mail suppressed',
				),
				'low'
			);
			return null;
		}

		$suppressed_count = is_array( $bucket ) ? (int) ( $bucket['suppressed_count'] ?? 0 ) : 0;
		$unique_ips_map   = is_array( $bucket ) && isset( $bucket['unique_ips_map'] ) && is_array( $bucket['unique_ips_map'] )
			? $bucket['unique_ips_map']
			: array();
		$first_suppressed = is_array( $bucket ) ? (int) ( $bucket['first_suppressed_at'] ?? 0 ) : 0;

		set_transient(
			$bucket_key,
			array(
				'next_allowed_at'     => $now + ( $cap_minutes * MINUTE_IN_SECONDS ),
				'suppressed_count'    => 0,
				'unique_ips_map'      => array(),
				'first_suppressed_at' => 0,
			),
			$cap_minutes * MINUTE_IN_SECONDS
		);

		arsort( $unique_ips_map );
		$sample = array_slice( array_keys( $unique_ips_map ), 0, 5 );

		return array(
			'suppressed_count' => $suppressed_count,
			'unique_ips'       => count( $unique_ips_map ),
			'since'            => $first_suppressed > 0 ? gmdate( 'Y-m-d H:i:s', $first_suppressed ) . ' UTC' : '',
			'sample_ips'       => $sample,
		);
	}

	/**
	 * Build the HTML + plain-text blocks for an admin security alert.
	 *
	 * @param string $event_label   Human-readable event label.
	 * @param string $ip_address    Triggering IP.
	 * @param array  $details       Threshold details.
	 * @param string $timestamp     Formatted timestamp.
	 * @param array  $burst_summary Suppression summary from reserve_event_burst_slot().
	 * @return array{html:string,text:string}
	 */
	private function build_alert_blocks( $event_label, $ip_address, $details, $timestamp, array $burst_summary = array() ) {
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

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_block', true ) ) {
			$duration = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_duration', 24 );
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

		$suppressed = isset( $burst_summary['suppressed_count'] ) ? (int) $burst_summary['suppressed_count'] : 0;
		if ( $suppressed > 0 ) {
			$unique_ips = (int) ( $burst_summary['unique_ips'] ?? 0 );
			$sample_ips = is_array( $burst_summary['sample_ips'] ?? null ) ? $burst_summary['sample_ips'] : array();
			$since      = (string) ( $burst_summary['since'] ?? '' );

			$html .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EEF2FF;border-radius:8px;margin:0 0 24px;">';
			$html .= '<tr><td style="padding:16px;">';
			$html .= '<p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#3730A3;">' . esc_html__( 'Burst suppression', 'reportedip-hive' ) . '</p>';
			$html .= '<p style="margin:0 0 8px;font-size:12px;color:#3730A3;line-height:1.5;">';
			$html .= esc_html(
				sprintf(
					/* translators: 1: number of suppressed alerts, 2: number of unique IPs, 3: ISO timestamp */
					_n(
						'%1$d additional alert of this type was suppressed since %3$s (from %2$d distinct IP).',
						'%1$d additional alerts of this type were suppressed since %3$s (from %2$d distinct IPs).',
						$suppressed,
						'reportedip-hive'
					),
					$suppressed,
					$unique_ips,
					$since
				)
			);
			$html .= '</p>';
			if ( ! empty( $sample_ips ) ) {
				$html .= '<p style="margin:0;font-size:12px;color:#3730A3;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;">';
				$html .= esc_html__( 'Top offenders:', 'reportedip-hive' ) . ' ' . esc_html( implode( ', ', $sample_ips ) );
				$html .= '</p>';
			}
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
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_block', true ) ) {
			$duration     = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_duration', 24 );
			$text_lines[] = '';
			$text_lines[] = sprintf(
				/* translators: %d: hours */
				__( 'Action: IP has been automatically blocked for %d hours.', 'reportedip-hive' ),
				$duration
			);
		}

		if ( $suppressed > 0 ) {
			$text_lines[] = '';
			$text_lines[] = sprintf(
				/* translators: 1: number of suppressed alerts, 2: number of unique IPs, 3: ISO timestamp */
				_n(
					'Burst suppression: %1$d additional alert of this type was suppressed since %3$s (from %2$d distinct IP).',
					'Burst suppression: %1$d additional alerts of this type were suppressed since %3$s (from %2$d distinct IPs).',
					$suppressed,
					'reportedip-hive'
				),
				$suppressed,
				(int) ( $burst_summary['unique_ips'] ?? 0 ),
				(string) ( $burst_summary['since'] ?? '' )
			);
			if ( ! empty( $sample_ips ) ) {
				$text_lines[] = __( 'Top offenders:', 'reportedip-hive' ) . ' ' . implode( ', ', $sample_ips );
			}
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
	 * Check for coordinated attacks.
	 *
	 * Runs two complementary detectors and returns the union of their hits
	 * (each row carries `time_window`, `unique_ips`, `total_attempts`):
	 *
	 *  1. Burst — ≥ 8 distinct IPs AND ≥ 30 attempts inside a single calendar
	 *     minute. Catches sharp simultaneous floods.
	 *  2. Distributed — ≥ {@see ReportedIP_Hive_Hardening_Mode::detect_min_ips()}
	 *     distinct IPs AND ≥ detect_min_attempts() across the rolling
	 *     detect_window_minutes() window. Catches botnets that rotate IPs over
	 *     several minutes and would otherwise slip under the per-minute burst
	 *     rule.
	 *
	 * Both detectors count individual `failed_login` rows in the `logs` table
	 * over a real `created_at` window — NOT `SUM(attempt_count)` from the
	 * aggregated `attempts` table, whose per-IP counter is cumulative (it
	 * accumulates across a rolling 1 h gap) and would over-count any IP that is
	 * merely active in the window with its full lifetime total. The logs table
	 * carries one timestamped row per attempt, so the magnitude reflects real
	 * in-window attempts (note: a `failed_login` is logged before an
	 * already-blocked IP is short-circuited, so a blocked attacker stops adding
	 * rows — the count tracks the active front line of an attack).
	 *
	 * The table lives under `base_prefix` (network-wide), so on Multisite the
	 * aggregate spans every site in the network — a distributed attack hitting
	 * many sub-sites is detected as one coordinated pattern.
	 *
	 * @return array<int,object>
	 */
	public function check_coordinated_attacks() {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_logs';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->base_prefix and a hardcoded suffix; safe.
		$coordinated_attacks = $wpdb->get_results(
			"SELECT
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as time_window,
                COUNT(DISTINCT ip_address) as unique_ips,
                COUNT(*) as total_attempts
             FROM $table_name
             WHERE created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 2 HOUR)
             AND event_type = 'failed_login'
             GROUP BY time_window
             HAVING unique_ips >= 8 AND total_attempts >= 30
             ORDER BY time_window DESC"
		);

		if ( ! is_array( $coordinated_attacks ) ) {
			$coordinated_attacks = array();
		}

		$distributed = $this->detect_distributed_attack_window();
		if ( null !== $distributed ) {
			array_unshift( $coordinated_attacks, $distributed );
		}

		/*
		 * One critical log per sweep, not one per bucket: the minute-bucket SQL
		 * rows and the prepended rolling-window row describe the same incident
		 * measured two ways, so logging every row produced duplicate
		 * `coordinated_attack_detected` events at the same instant. Emit only the
		 * strongest reason; the full row set is still returned for the hardening
		 * activation path. Suppression is keyed on the chosen window so an hourly
		 * cron re-scan of the 2 h lookback does not re-log the same incident.
		 */
		$strongest = $this->strongest_coordinated_reason( $coordinated_attacks );
		if ( is_array( $strongest ) && '' !== (string) $strongest['time_window'] ) {
			$log_key = class_exists( 'ReportedIP_Hive_Hardening_Mode' )
				? ReportedIP_Hive_Hardening_Mode::log_marker_key( (string) $strongest['time_window'] )
				: '';

			if ( '' === $log_key || ! get_site_transient( $log_key ) ) {
				$this->logger->log_security_event(
					'coordinated_attack_detected',
					'multiple',
					array(
						'time_window'    => $strongest['time_window'],
						'unique_ips'     => $strongest['unique_ips'],
						'total_attempts' => $strongest['total_attempts'],
					),
					'critical'
				);

				if ( '' !== $log_key ) {
					set_site_transient( $log_key, 1, 2 * HOUR_IN_SECONDS );
				}
			}
		}

		return $coordinated_attacks;
	}

	/**
	 * Distributed-attack detector — rolling-window aggregate.
	 *
	 * Counts distinct IPs and real `failed_login` events over the configurable
	 * sliding window (default 10 min) and returns a synthetic row when the
	 * configured thresholds are breached. Reads individual rows from the `logs`
	 * table (one per attempt) rather than `SUM(attempt_count)` from the
	 * cumulative `attempts` table, so the magnitude reflects in-window attempts
	 * and not an IP's lifetime counter. The synthetic `time_window` is a stable
	 * per-window bucket label so the existing suppression markers do not re-log
	 * the same window on every cron sweep.
	 *
	 * @return object|null Row with `time_window`, `unique_ips`, `total_attempts`, or null.
	 * @since  2.0.29
	 */
	private function detect_distributed_attack_window() {
		global $wpdb;

		if ( ! class_exists( 'ReportedIP_Hive_Hardening_Mode' ) ) {
			return null;
		}

		$window     = ReportedIP_Hive_Hardening_Mode::detect_window_minutes();
		$table_name = $wpdb->base_prefix . 'reportedip_hive_logs';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->base_prefix and a hardcoded suffix; interval is a prepared integer.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT ip_address) as unique_ips,
                        COUNT(*) as total_attempts
                 FROM $table_name
                 WHERE created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)
                 AND event_type = 'failed_login'",
				$window
			)
		);

		if ( ! $row ) {
			return null;
		}

		$unique_ips     = (int) $row->unique_ips;
		$total_attempts = (int) $row->total_attempts;

		if ( ! ReportedIP_Hive_Hardening_Mode::breaches_distributed_thresholds( $unique_ips, $total_attempts ) ) {
			return null;
		}

		return $this->build_rolling_reason_row( $unique_ips, $total_attempts, $window );
	}

	/**
	 * Build the synthetic coordinated-attack row for a rolling-window hit.
	 *
	 * Separated from the query so the row shape and bucket labelling are unit
	 * testable without a database.
	 *
	 * @param int      $unique_ips     Distinct IPs in the window.
	 * @param int      $total_attempts Summed attempts in the window.
	 * @param int      $window_minutes Window length used for the bucket label.
	 * @param int|null $now            Override timestamp (testing); defaults to time().
	 * @return object
	 * @since  2.0.29
	 */
	public function build_rolling_reason_row( $unique_ips, $total_attempts, $window_minutes, $now = null ) {
		$now = null === $now ? time() : (int) $now;

		$row                 = new stdClass();
		$row->time_window    = ReportedIP_Hive_Hardening_Mode::rolling_window_bucket_label( $window_minutes, $now );
		$row->unique_ips     = (int) $unique_ips;
		$row->total_attempts = (int) $total_attempts;

		return $row;
	}

	/**
	 * Pick the strongest reason out of `check_coordinated_attacks()` rows.
	 *
	 * Used by both the realtime hook and the cron sweep so the same
	 * Hardening_Mode::activate() call site can hand over the row with the
	 * highest unique-IP / total-attempts count.
	 *
	 * @param array $rows Result of {@see check_coordinated_attacks()}.
	 * @return array|null `{unique_ips, total_attempts, time_window}` or null.
	 * @since  2.0.8
	 */
	public function strongest_coordinated_reason( array $rows ) {
		if ( empty( $rows ) ) {
			return null;
		}
		$strongest = $rows[0];
		foreach ( $rows as $attack ) {
			if ( (int) $attack->unique_ips > (int) $strongest->unique_ips
				|| ( (int) $attack->unique_ips === (int) $strongest->unique_ips
					&& (int) $attack->total_attempts > (int) $strongest->total_attempts )
			) {
				$strongest = $attack;
			}
		}
		return array(
			'unique_ips'     => (int) $strongest->unique_ips,
			'total_attempts' => (int) $strongest->total_attempts,
			'time_window'    => (string) $strongest->time_window,
		);
	}

	/**
	 * Realtime coordinated-attack probe.
	 *
	 * Called from `check_failed_login_threshold()` after every `track_attempt()`.
	 * Debounced via a 60-second site-transient so we run the (cheap) aggregate
	 * query at most once per minute regardless of incoming login volume.
	 *
	 * Short-circuits when the hardening feature is unavailable (Free tier or
	 * master toggle off), the realtime detection toggle is off, or hardening
	 * is already active.
	 *
	 * @return void
	 * @since 2.0.8
	 */
	private function maybe_check_coordinated_realtime() {
		if ( ! ReportedIP_Hive_Hardening_Mode::is_available() ) {
			return;
		}
		if ( ! ReportedIP_Hive_Hardening_Mode::is_realtime_detection_enabled() ) {
			return;
		}
		if ( ReportedIP_Hive_Hardening_Mode::is_active() ) {
			return;
		}
		if ( get_site_transient( ReportedIP_Hive_Hardening_Mode::TRANSIENT_DEBOUNCE ) ) {
			return;
		}
		set_site_transient(
			ReportedIP_Hive_Hardening_Mode::TRANSIENT_DEBOUNCE,
			1,
			ReportedIP_Hive_Hardening_Mode::DEBOUNCE_SECONDS
		);

		$attacks = $this->check_coordinated_attacks();
		$reason  = $this->strongest_coordinated_reason( $attacks );
		if ( null === $reason ) {
			return;
		}

		ReportedIP_Hive_Hardening_Mode::activate( $reason, 'realtime' );
	}
}
