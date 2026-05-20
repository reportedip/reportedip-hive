<?php
/**
 * Hardening Mode — temporary site-wide threshold tightening on coordinated attack.
 *
 * Activated by {@see ReportedIP_Hive_Security_Monitor::check_coordinated_attacks()}
 * (and the new realtime debounce in `check_failed_login_threshold()`) when a
 * distributed brute-force pattern is detected. For the configured duration
 * (default 60 min) effective thresholds are clamped to the hardening defaults:
 *
 * - failed_login_threshold (default 5 / 15 min) → hardening default 2 / 5 min
 * - block_threshold (Reputation, default 75 %) → hardening default 60 %
 *
 * The clamp is always {@code min( admin, hardening )} — administrators who have
 * configured stricter thresholds manually do not get them softened during
 * hardening.
 *
 * Gated on the PRO tier via {@see ReportedIP_Hive_Mode_Manager::feature_status('hardening_mode')}.
 *
 * State is held in a single site-wide transient
 * `reportedip_hive_hardening_until` (unix timestamp). `set_site_transient` is
 * used so the marker is multisite-aware (network-wide).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.8
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static helper class for the Hardening Mode state + override thresholds.
 *
 * @since 2.0.8
 */
final class ReportedIP_Hive_Hardening_Mode {

	const TRANSIENT_UNTIL    = 'reportedip_hive_hardening_until';
	const TRANSIENT_REASON   = 'reportedip_hive_hardening_reason';
	const TRANSIENT_LOGGED   = 'reportedip_hive_hardening_logged';
	const TRANSIENT_DEBOUNCE = 'reportedip_hive_coordinated_check_debounce';

	const DEBOUNCE_SECONDS = 60;

	const DEFAULT_DURATION_MINUTES = 60;
	const DEFAULT_LOGIN_THRESHOLD  = 2;
	const DEFAULT_LOGIN_TIMEFRAME  = 5;
	const DEFAULT_BLOCK_THRESHOLD  = 60;
	const DEFAULT_MASTER_ENABLED   = false;
	const DEFAULT_REALTIME_ENABLED = true;

	/**
	 * Whether the hardening mode is currently scharfgeschaltet.
	 *
	 * Also opportunistically logs the natural-expiry event the first time it is
	 * observed after the transient lapsed.
	 *
	 * @return bool
	 */
	public static function is_active() {
		$until = (int) get_site_transient( self::TRANSIENT_UNTIL );
		if ( $until > time() ) {
			return true;
		}

		if ( $until > 0 && ! get_site_transient( self::TRANSIENT_LOGGED ) ) {
			set_site_transient( self::TRANSIENT_LOGGED, 1, HOUR_IN_SECONDS );
			self::log_event( 'hardening_mode_deactivated', array( 'actor' => 'expired' ), 'low' );
			delete_site_transient( self::TRANSIENT_UNTIL );
			delete_site_transient( self::TRANSIENT_REASON );
		}

		return false;
	}

	/**
	 * Unix timestamp at which the current hardening window ends, or null when inactive.
	 *
	 * @return int|null
	 */
	public static function expires_at() {
		$until = (int) get_site_transient( self::TRANSIENT_UNTIL );
		return $until > time() ? $until : null;
	}

	/**
	 * Cached reason payload that triggered the current activation (or null).
	 *
	 * @return array|null
	 */
	public static function current_reason() {
		$reason = get_site_transient( self::TRANSIENT_REASON );
		return is_array( $reason ) ? $reason : null;
	}

	/**
	 * Whether the feature is licensed + master-toggle on.
	 *
	 * @return bool
	 */
	public static function is_available() {
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_enabled', self::DEFAULT_MASTER_ENABLED ) ) {
			return false;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'hardening_mode' );
		return ! empty( $status['available'] );
	}

	/**
	 * Whether the realtime detection hook should fire in `wp_login_failed`.
	 *
	 * @return bool
	 */
	public static function is_realtime_detection_enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_realtime_detection', self::DEFAULT_REALTIME_ENABLED );
	}

	/**
	 * Activate the hardening window. Idempotent — only extends the window when
	 * the new reason is more severe (more unique IPs / total attempts) or when
	 * the remaining TTL has dropped below 50 % of the configured duration.
	 *
	 * @param array  $reason  {unique_ips, total_attempts, time_window}
	 * @param string $trigger 'realtime'|'cron'|'manual'
	 * @return bool True when (re-)activated, false when gated out or skipped.
	 */
	public static function activate( array $reason, $trigger = 'realtime' ) {
		if ( ! self::is_available() ) {
			return false;
		}

		$duration_minutes = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_duration_minutes', self::DEFAULT_DURATION_MINUTES );
		$duration_minutes = max( 1, min( 360, $duration_minutes ) );
		$duration_seconds = $duration_minutes * MINUTE_IN_SECONDS;

		$existing           = (int) get_site_transient( self::TRANSIENT_UNTIL );
		$now                = time();
		$existing_remaining = $existing > $now ? ( $existing - $now ) : 0;

		$existing_reason = self::current_reason();
		$is_more_severe  = self::reason_is_more_severe( $reason, $existing_reason );
		$ttl_low         = $existing_remaining > 0 && $existing_remaining < ( $duration_seconds / 2 );

		if ( $existing_remaining > 0 && ! $is_more_severe && ! $ttl_low ) {
			return false;
		}

		$until = $now + $duration_seconds;

		$retain_ttl = $duration_seconds + DAY_IN_SECONDS;
		set_site_transient( self::TRANSIENT_UNTIL, $until, $retain_ttl );
		set_site_transient(
			self::TRANSIENT_REASON,
			array(
				'unique_ips'     => isset( $reason['unique_ips'] ) ? (int) $reason['unique_ips'] : 0,
				'total_attempts' => isset( $reason['total_attempts'] ) ? (int) $reason['total_attempts'] : 0,
				'time_window'    => isset( $reason['time_window'] ) ? (string) $reason['time_window'] : '',
				'trigger'        => (string) $trigger,
				'activated_at'   => $now,
			),
			$retain_ttl
		);
		delete_site_transient( self::TRANSIENT_LOGGED );

		self::log_event(
			'hardening_mode_activated',
			array(
				'unique_ips'       => (int) ( $reason['unique_ips'] ?? 0 ),
				'total_attempts'   => (int) ( $reason['total_attempts'] ?? 0 ),
				'time_window'      => (string) ( $reason['time_window'] ?? '' ),
				'duration_seconds' => $duration_seconds,
				'trigger'          => (string) $trigger,
			),
			'high'
		);

		return true;
	}

	/**
	 * Manually clear the hardening window (UI / WP-CLI / AJAX).
	 *
	 * @param string $actor 'admin'|'cli'|'expired'
	 * @return void
	 */
	public static function deactivate( $actor = 'admin' ) {
		$was_active = (int) get_site_transient( self::TRANSIENT_UNTIL ) > time();
		delete_site_transient( self::TRANSIENT_UNTIL );
		delete_site_transient( self::TRANSIENT_REASON );
		delete_site_transient( self::TRANSIENT_LOGGED );
		if ( $was_active ) {
			self::log_event( 'hardening_mode_deactivated', array( 'actor' => (string) $actor ), 'low' );
		}
	}

	/**
	 * Effective failed-login threshold during hardening.
	 *
	 * @param int $default Admin-configured value.
	 * @return int
	 */
	public static function effective_failed_login_threshold( $default ) {
		if ( ! self::is_active() ) {
			return (int) $default;
		}
		$hard = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_login_threshold', self::DEFAULT_LOGIN_THRESHOLD );
		$hard = max( 1, min( 10, $hard ) );
		return min( (int) $default, $hard );
	}

	/**
	 * Effective failed-login timeframe (minutes) during hardening.
	 *
	 * @param int $default Admin-configured value (minutes).
	 * @return int
	 */
	public static function effective_failed_login_timeframe( $default ) {
		if ( ! self::is_active() ) {
			return (int) $default;
		}
		$hard = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_login_timeframe', self::DEFAULT_LOGIN_TIMEFRAME );
		$hard = max( 1, min( 60, $hard ) );
		return min( (int) $default, $hard );
	}

	/**
	 * Effective reputation-block threshold (percentage) during hardening.
	 *
	 * @param int $default Admin-configured value.
	 * @return int
	 */
	public static function effective_block_threshold( $default ) {
		if ( ! self::is_active() ) {
			return (int) $default;
		}
		$hard = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_block_threshold', self::DEFAULT_BLOCK_THRESHOLD );
		$hard = max( 10, min( 100, $hard ) );
		return min( (int) $default, $hard );
	}

	/**
	 * Whether a new reason should preempt the currently stored one.
	 *
	 * @param array      $candidate
	 * @param array|null $existing
	 * @return bool
	 */
	private static function reason_is_more_severe( array $candidate, $existing ) {
		if ( ! is_array( $existing ) ) {
			return true;
		}
		$c_ips      = (int) ( $candidate['unique_ips'] ?? 0 );
		$e_ips      = (int) ( $existing['unique_ips'] ?? 0 );
		$c_attempts = (int) ( $candidate['total_attempts'] ?? 0 );
		$e_attempts = (int) ( $existing['total_attempts'] ?? 0 );
		if ( $c_ips > $e_ips ) {
			return true;
		}
		if ( $c_ips === $e_ips && $c_attempts > $e_attempts ) {
			return true;
		}
		return false;
	}

	/**
	 * Write a structured log entry via the central Logger.
	 *
	 * @param string $event
	 * @param array  $details
	 * @param string $severity
	 * @return void
	 */
	private static function log_event( $event, array $details, $severity ) {
		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}
		ReportedIP_Hive_Logger::get_instance()->log_security_event( $event, 'system', $details, $severity );
	}
}
