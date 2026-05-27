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

	const TRANSIENT_UNTIL         = 'reportedip_hive_hardening_until';
	const TRANSIENT_REASON        = 'reportedip_hive_hardening_reason';
	const TRANSIENT_LOGGED        = 'reportedip_hive_hardening_logged';
	const TRANSIENT_DEBOUNCE      = 'reportedip_hive_coordinated_check_debounce';
	const TRANSIENT_WINDOW_PREFIX = 'reportedip_hive_hardening_seen_';
	const TRANSIENT_LOG_PREFIX    = 'reportedip_hive_hardening_logged_window_';

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
	 * Activate the hardening window.
	 *
	 * Idempotency rules (the marker stores the canonical strongest reason
	 * for its time_window, so suppression survives the lazy expiry of
	 * `TRANSIENT_REASON` and the natural-expiry wipe in {@see is_active()}):
	 *
	 *  - When the candidate `time_window` has a live marker AND the candidate
	 *    is not strictly more severe than what the marker remembers, return
	 *    false. This is what stops the hourly cron sweep from re-emitting
	 *    `hardening_mode_activated` for the same row in
	 *    `wp_reportedip_hive_attempts` — even after the hardening window
	 *    expired naturally and `TRANSIENT_REASON` was deleted.
	 *  - When the candidate is strictly more severe than the comparison
	 *    reason (live REASON if present, otherwise the marker payload), the
	 *    window re-arms: replace `TRANSIENT_UNTIL`, `TRANSIENT_REASON` AND
	 *    the marker payload; emit `hardening_mode_activated` (severity high).
	 *  - When the remaining TTL drops below 50 % of the configured duration
	 *    and the candidate is not more severe, only extend `TRANSIENT_UNTIL`
	 *    AND refresh the marker TTL (preserving the canonical payload), then
	 *    emit `hardening_mode_extended` (severity low). The stronger original
	 *    reason stays visible in `TRANSIENT_REASON` / on the UI.
	 *  - {@see deactivate()} clears the marker for the live reason's time
	 *    window so an admin override is not silently undone by the next
	 *    cron sweep.
	 *
	 * @param array  $reason  {unique_ips, total_attempts, time_window}
	 * @param string $trigger 'realtime'|'cron'|'manual'
	 * @return bool True when (re-)activated or TTL extended, false when gated out or skipped.
	 */
	public static function activate( array $reason, $trigger = 'realtime' ) {
		if ( ! self::is_available() ) {
			return false;
		}

		$duration_minutes = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_duration_minutes', self::DEFAULT_DURATION_MINUTES );
		$duration_minutes = max( 1, min( 360, $duration_minutes ) );
		$duration_seconds = $duration_minutes * MINUTE_IN_SECONDS;
		$retain_ttl       = $duration_seconds + DAY_IN_SECONDS;

		$existing           = (int) get_site_transient( self::TRANSIENT_UNTIL );
		$now                = time();
		$existing_remaining = $existing > $now ? ( $existing - $now ) : 0;

		$existing_reason = self::current_reason();

		$window_key   = self::window_marker_key( (string) ( $reason['time_window'] ?? '' ) );
		$marker_value = '' !== $window_key ? get_site_transient( $window_key ) : false;
		$window_seen  = is_array( $marker_value );

		/*
		 * Pick the reference reason to compare the candidate against. The
		 * marker is the source of truth that survives REASON expiry; the
		 * live REASON wins only while it's actually present, so a stronger
		 * candidate during the active window can still upgrade the trigger
		 * payload.
		 */
		if ( is_array( $existing_reason ) ) {
			$reference_reason = $existing_reason;
		} elseif ( $window_seen ) {
			$reference_reason = $marker_value;
		} else {
			$reference_reason = null;
		}

		$is_more_severe = self::reason_is_more_severe( $reason, $reference_reason );
		$ttl_low        = $existing_remaining > 0 && $existing_remaining < ( $duration_seconds / 2 );

		if ( $window_seen && ! $is_more_severe ) {
			return false;
		}

		if ( $existing_remaining > 0 && ! $is_more_severe ) {
			if ( ! $ttl_low ) {
				return false;
			}

			$until = $now + $duration_seconds;
			set_site_transient( self::TRANSIENT_UNTIL, $until, $retain_ttl );

			if ( '' !== $window_key ) {
				$marker_payload = is_array( $marker_value ) ? $marker_value : array(
					'unique_ips'     => isset( $reason['unique_ips'] ) ? (int) $reason['unique_ips'] : 0,
					'total_attempts' => isset( $reason['total_attempts'] ) ? (int) $reason['total_attempts'] : 0,
					'time_window'    => isset( $reason['time_window'] ) ? (string) $reason['time_window'] : '',
					'trigger'        => (string) $trigger,
					'activated_at'   => $now,
				);
				set_site_transient( $window_key, $marker_payload, $retain_ttl );
			}

			self::log_event(
				'hardening_mode_extended',
				array(
					'duration_seconds' => $duration_seconds,
					'trigger'          => (string) $trigger,
					'preserved_reason' => is_array( $existing_reason ) ? $existing_reason : ( is_array( $marker_value ) ? $marker_value : array() ),
				),
				'low'
			);

			return true;
		}

		$reason_payload = array(
			'unique_ips'     => isset( $reason['unique_ips'] ) ? (int) $reason['unique_ips'] : 0,
			'total_attempts' => isset( $reason['total_attempts'] ) ? (int) $reason['total_attempts'] : 0,
			'time_window'    => isset( $reason['time_window'] ) ? (string) $reason['time_window'] : '',
			'trigger'        => (string) $trigger,
			'activated_at'   => $now,
		);

		$until = $now + $duration_seconds;
		set_site_transient( self::TRANSIENT_UNTIL, $until, $retain_ttl );
		set_site_transient( self::TRANSIENT_REASON, $reason_payload, $retain_ttl );
		if ( '' !== $window_key ) {
			set_site_transient( $window_key, $reason_payload, $retain_ttl );
		}
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
	 * Build the per-time-window suppression transient key (state marker).
	 *
	 * @param string $time_window Server-formatted DATE_FORMAT(last_attempt, '%Y-%m-%d %H:%i') value.
	 * @return string Empty string when no usable window — caller must skip the marker write/read.
	 * @since 2.0.16
	 */
	public static function window_marker_key( $time_window ) {
		$time_window = trim( (string) $time_window );
		if ( '' === $time_window ) {
			return '';
		}
		return self::TRANSIENT_WINDOW_PREFIX . md5( $time_window );
	}

	/**
	 * Build the per-time-window log-suppression transient key (cron-noise control).
	 *
	 * Used by {@see ReportedIP_Hive_Security_Monitor::check_coordinated_attacks()}
	 * to log each pattern at most once per retention window, so the hourly cron
	 * sweep does not re-emit critical `coordinated_attack_detected` events for
	 * the same minute-bucket every hour while the row remains in the 2 h SQL
	 * lookback.
	 *
	 * @param string $time_window Server-formatted DATE_FORMAT(last_attempt, '%Y-%m-%d %H:%i') value.
	 * @return string Empty string when no usable window — caller must skip the marker write/read.
	 * @since 2.0.16
	 */
	public static function log_marker_key( $time_window ) {
		$time_window = trim( (string) $time_window );
		if ( '' === $time_window ) {
			return '';
		}
		return self::TRANSIENT_LOG_PREFIX . md5( $time_window );
	}

	/**
	 * Manually clear the hardening window (UI / WP-CLI / AJAX).
	 *
	 * Also clears the per-window marker for the live reason so an admin
	 * override is not silently undone by the next cron sweep that finds
	 * the same time_window still in the 2 h SQL lookback.
	 *
	 * @param string $actor 'admin'|'cli'|'expired'
	 * @return void
	 */
	public static function deactivate( $actor = 'admin' ) {
		$was_active     = (int) get_site_transient( self::TRANSIENT_UNTIL ) > time();
		$current_reason = self::current_reason();

		if ( is_array( $current_reason ) && ! empty( $current_reason['time_window'] ) ) {
			$window_key = self::window_marker_key( (string) $current_reason['time_window'] );
			if ( '' !== $window_key ) {
				delete_site_transient( $window_key );
			}
			$log_key = self::log_marker_key( (string) $current_reason['time_window'] );
			if ( '' !== $log_key ) {
				delete_site_transient( $log_key );
			}
		}

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
