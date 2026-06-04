<?php
/**
 * Cron Handler Class for ReportedIP Hive.
 *
 * Handles all scheduled cron jobs: cleanup, reputation sync,
 * queue processing, and quota refresh.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Cron_Handler
 *
 * Manages all cron-related functionality for the ReportedIP Hive plugin.
 */
class ReportedIP_Hive_Cron_Handler {

	/**
	 * Transient key used to serialise queue-cron runs. WP-Cron, an external
	 * cron, and a manual admin trigger can all fire the same hook within
	 * milliseconds; the lock keeps the recovery sweep + per-row claim from
	 * racing with a parallel worker.
	 */
	const QUEUE_LOCK_TRANSIENT = 'reportedip_hive_queue_lock';

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
	 * Constructor - registers cron hooks and custom intervals
	 *
	 * @param ReportedIP_Hive_Security_Monitor $security_monitor Security monitor instance.
	 */
	public function __construct( $security_monitor ) {
		$this->logger           = ReportedIP_Hive_Logger::get_instance();
		$this->api_client       = ReportedIP_Hive_API::get_instance();
		$this->ip_manager       = ReportedIP_Hive_IP_Manager::get_instance();
		$this->database         = ReportedIP_Hive_Database::get_instance();
		$this->security_monitor = $security_monitor;

		add_action( 'reportedip_hive_cleanup', array( $this, 'cron_cleanup' ) );
		add_action( 'reportedip_hive_sync_reputation', array( $this, 'cron_sync_reputation' ) );
		add_action( 'reportedip_hive_process_queue', array( $this, 'cron_process_queue' ) );
		add_action( 'reportedip_hive_refresh_quota', array( $this, 'cron_refresh_quota' ) );

		add_filter( 'cron_schedules', array( __CLASS__, 'add_cron_intervals' ) );
	}

	/**
	 * Plugin cron jobs: hook → recurrence slug. Single source of truth for
	 * schedule, unschedule and self-heal. Custom intervals
	 * (`fifteen_minutes`, `six_hours`) are registered via
	 * {@see add_cron_intervals()}.
	 *
	 * @var array<string,string>
	 */
	private const JOBS = array(
		'reportedip_hive_cleanup'         => 'daily',
		'reportedip_hive_sync_reputation' => 'hourly',
		'reportedip_hive_process_queue'   => 'fifteen_minutes',
		'reportedip_hive_refresh_quota'   => 'six_hours',
	);

	/**
	 * Schedule cron jobs (static version for activation hook + self-heal).
	 *
	 * The Cron_Handler instance is not constructed during activation, so the
	 * cron_schedules filter from the constructor is not yet attached. Register
	 * the static handler here so wp_schedule_event() finds the custom intervals.
	 *
	 * On Multisite the schedule is registered only on the main site so a
	 * 100-site network does not run 100 parallel queue workers.
	 */
	public static function schedule_cron_jobs_static() {
		if ( is_multisite() && ! is_main_site() ) {
			return;
		}
		add_filter( 'cron_schedules', array( __CLASS__, 'add_cron_intervals' ) );
		foreach ( self::JOBS as $hook => $recurrence ) {
			if ( ! wp_next_scheduled( $hook ) ) {
				wp_schedule_event( time(), $recurrence, $hook );
			}
		}
	}

	/**
	 * Clear cron jobs (static version for deactivation hook).
	 */
	public static function clear_cron_jobs_static() {
		foreach ( self::JOBS as $hook => $_ ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/**
	 * Self-heal: re-register any missing cron job. Wired from
	 * `admin_init` on the main site so a main-site change in a Multisite
	 * network does not leave the network without crons.
	 */
	public static function ensure_scheduled() {
		self::schedule_cron_jobs_static();
	}

	/**
	 * Returns the list of registered cron hook names. Used by tests.
	 *
	 * @return string[]
	 */
	public static function get_hook_names() {
		return array_keys( self::JOBS );
	}

	/**
	 * Add custom cron intervals (static so activation-time scheduling works
	 * before any Cron_Handler instance exists).
	 *
	 * @param array $schedules Existing cron schedules.
	 * @return array Modified schedules.
	 */
	public static function add_cron_intervals( $schedules ) {
		if ( ! isset( $schedules['fifteen_minutes'] ) ) {
			$schedules['fifteen_minutes'] = array(
				'interval' => 15 * MINUTE_IN_SECONDS,
				'display'  => __( 'Every 15 Minutes', 'reportedip-hive' ),
			);
		}
		if ( ! isset( $schedules['six_hours'] ) ) {
			$schedules['six_hours'] = array(
				'interval' => 6 * HOUR_IN_SECONDS,
				'display'  => __( 'Every 6 Hours', 'reportedip-hive' ),
			);
		}
		return $schedules;
	}

	/**
	 * Cron job: Daily cleanup
	 */
	public function cron_cleanup() {
		try {
			$retention_days = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_data_retention_days', 30 );
			$anonymize_days = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_anonymize_days', 7 );

			$anonymized = $this->database->anonymize_old_data( $anonymize_days );

			$cleaned_logs    = $this->database->cleanup_old_data( $retention_days );
			$expired_entries = $this->ip_manager->cleanup_expired_entries();

			$this->logger->info(
				'Daily cleanup completed',
				'system',
				array(
					'anonymized_entries' => $anonymized,
					'cleaned_logs'       => $cleaned_logs,
					'expired_entries'    => $expired_entries,
					'retention_days'     => $retention_days,
					'anonymize_days'     => $anonymize_days,
				)
			);

			if ( class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
				ReportedIP_Hive_Two_Factor::cleanup_expired_devices();
			}

			$this->database->update_daily_stats( 'cleanup_runs' );

		} catch ( Exception $e ) {
			$this->logger->critical( 'Daily cleanup failed: ' . $e->getMessage(), 'system' );
		}
	}

	/**
	 * Cron job: Process API queue and sync reputation
	 */
	public function cron_sync_reputation() {
		try {
			$coordinated_attacks = $this->security_monitor->check_coordinated_attacks();
			if ( ! empty( $coordinated_attacks ) && class_exists( 'ReportedIP_Hive_Hardening_Mode' ) ) {
				$reason = $this->security_monitor->strongest_coordinated_reason( $coordinated_attacks );
				if ( null !== $reason ) {
					ReportedIP_Hive_Hardening_Mode::activate( $reason, 'cron' );
				}
			}
		} catch ( Exception $e ) {
			$this->logger->critical( 'Reputation sync failed: ' . $e->getMessage(), 'system' );
		}
	}

	/**
	 * Cron job: Process API report queue (runs every 15 minutes).
	 *
	 * Acquires a 5-minute transient lock to prevent two workers (e.g. WP-Cron
	 * + system cron + concurrent admin trigger) from running the queue at the
	 * same time. The recovery sweep inside `process_report_queue()` would
	 * otherwise race with a parallel run on the same row.
	 */
	public function cron_process_queue() {
		if ( get_transient( self::QUEUE_LOCK_TRANSIENT ) ) {
			$this->logger->info(
				'Queue processing skipped: another worker holds the lock',
				'system',
				array( 'lock_key' => self::QUEUE_LOCK_TRANSIENT )
			);
			return;
		}

		set_transient( self::QUEUE_LOCK_TRANSIENT, 1, 5 * MINUTE_IN_SECONDS );

		try {
			$queue_result = $this->api_client->process_report_queue( REPORTEDIP_QUEUE_BATCH_SIZE );

			if ( false === $queue_result ) {
				$this->logger->info(
					'Queue processing skipped: api not usable (mode or configuration)',
					'system',
					array()
				);
			} elseif ( $queue_result && ! isset( $queue_result['skipped'] ) ) {
				$this->logger->info(
					'Queue processed (15min cron)',
					'system',
					array(
						'processed' => $queue_result['processed'],
						'errors'    => $queue_result['errors'],
						'total'     => $queue_result['total'],
						'recovered' => $queue_result['recovered'] ?? array(
							'reset'  => 0,
							'failed' => 0,
						),
					)
				);
			} elseif ( isset( $queue_result['skipped'] ) && $queue_result['skipped'] ) {
				$this->logger->info(
					'Queue processing skipped',
					'system',
					array(
						'reason'     => $queue_result['reason'] ?? null,
						'reset_time' => $queue_result['reset_time'] ?? null,
					)
				);
			}
		} catch ( \Throwable $e ) {
			$this->logger->error( 'Queue processing failed: ' . $e->getMessage(), 'system' );
		} finally {
			delete_transient( self::QUEUE_LOCK_TRANSIENT );
		}
	}

	/**
	 * Cron job: Refresh API quota (runs every 6 hours)
	 */
	public function cron_refresh_quota() {
		try {
			$quota = $this->api_client->refresh_api_quota();

			if ( $quota ) {
				$this->logger->info(
					'API quota refreshed',
					'system',
					array(
						'remaining_reports' => $quota['remaining_reports'],
						'daily_limit'       => $quota['daily_report_limit'],
						'reset_time'        => $quota['reset_time'],
						'user_role'         => $quota['user_role'],
					)
				);

				$queue_size = $this->database->get_queue_size();
				if ( $queue_size > 0 && $quota['remaining_reports'] === 0 ) {
					$this->logger->warning(
						'Queue building up with no quota',
						'system',
						array(
							'queue_size'  => $queue_size,
							'quota_limit' => $quota['daily_report_limit'],
							'user_role'   => $quota['user_role'],
						)
					);
				}
			}
		} catch ( Exception $e ) {
			$this->logger->error( 'Quota refresh failed: ' . $e->getMessage(), 'system' );
		}

		try {
			$relay = $this->api_client->get_relay_quota( true );
			if ( empty( $relay['error'] ) ) {
				$this->logger->info(
					'Relay quota refreshed',
					'system',
					array(
						'tier'                => $relay['tier'] ?? null,
						'mail_used'           => $relay['mail']['queued_total'] ?? $relay['mail']['used'] ?? null,
						'mail_limit'          => $relay['mail']['limit'] ?? null,
						'mail_bundle_balance' => $relay['mail']['bundle_balance'] ?? $relay['mail_bundle_balance'] ?? null,
						'sms_used'            => $relay['sms']['queued_total'] ?? $relay['sms']['used'] ?? null,
						'sms_limit'           => $relay['sms']['limit'] ?? null,
						'sms_bundle_balance'  => $relay['sms']['bundle_balance'] ?? $relay['sms_bundle_balance'] ?? null,
					)
				);

				if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
					$snapshot = ReportedIP_Hive_Mode_Manager::get_instance()->get_relay_quota_snapshot();

					/**
					 * Fires after a successful /relay-quota response was cached.
					 *
					 * Consumers: {@see ReportedIP_Hive_Quota_Notifier::evaluate()} dispatches
					 * 80 % / 100 % stage mails to the admin recipient list.
					 *
					 * @param array $snapshot Normalised quota snapshot.
					 * @since 2.0.16
					 */
					do_action( 'reportedip_hive_relay_quota_refreshed', $snapshot );

					foreach ( array( 'mail', 'sms' ) as $channel ) {
						$used  = (int) ( $snapshot[ $channel ]['used'] ?? 0 );
						$limit = $snapshot[ $channel ]['limit'] ?? null;
						if ( null !== $limit && (int) $limit > 0 && $used < (int) $limit ) {
							ReportedIP_Hive_Mode_Manager::clear_cap_state( $channel );
						}
					}
				}
			} else {
				$this->logger->warning(
					'Relay quota refresh failed',
					'system',
					array( 'error' => (string) $relay['error'] )
				);
			}
		} catch ( Exception $e ) {
			$this->logger->error( 'Relay quota refresh failed: ' . $e->getMessage(), 'system' );
		}
	}

	/**
	 * Manual trigger for cron jobs (for testing)
	 *
	 * @param string $job_name Job name to trigger ('cleanup', 'sync', 'queue', 'quota', 'all').
	 * @return bool True if triggered successfully, false on insufficient permissions.
	 */
	public function trigger_cron_manually( $job_name = 'all' ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return false;
		}

		switch ( $job_name ) {
			case 'cleanup':
				$this->cron_cleanup();
				break;
			case 'sync':
				$this->cron_sync_reputation();
				break;
			case 'queue':
				$this->cron_process_queue();
				break;
			case 'quota':
				$this->cron_refresh_quota();
				break;
			case 'all':
			default:
				$this->cron_cleanup();
				$this->cron_sync_reputation();
				$this->cron_process_queue();
				$this->cron_refresh_quota();
				break;
		}

		return true;
	}
}
