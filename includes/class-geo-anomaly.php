<?php
/**
 * Geographic Anomaly Detection.
 *
 * Watches successful logins. When the country / ASN seen for this user
 * differs from anything observed in the configured rolling window
 * (default 90 days), the event is logged as `geo_anomaly` and (optionally)
 * the user's trusted-device cookies are revoked so the next login forces a
 * fresh 2FA challenge.
 *
 * Country / ASN data comes from the same reputation lookup the plugin
 * already does in pre-auth — there is no second external call. If the
 * service has no reputation entry yet (cold IP) the sensor is silent, by
 * design: a brand-new IP without any geo data is not enough signal to act.
 *
 * Per-user history lives in `user_meta` and is capped at 12 entries
 * (LRU-trimmed) to keep the row tiny.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_Geo_Anomaly {

	private const META_HISTORY = 'reportedip_hive_geo_history';
	private const HISTORY_MAX  = 12;

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Geo_Anomaly|null
	 */
	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'wp_login', array( $this, 'on_login' ), 20, 2 );
	}

	/**
	 * @param string  $user_login Login name (unused — kept for hook signature).
	 * @param WP_User $user       WP_User object.
	 */
	public function on_login( $user_login, $user ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		unset( $user_login );

		if ( ! get_option( 'reportedip_hive_monitor_geo_anomaly', true ) ) {
			return;
		}
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( '' === $ip || 'unknown' === $ip ) {
			return;
		}

		$reputation = $this->fetch_reputation( $ip );
		if ( empty( $reputation ) ) {
			return;
		}

		$country = $this->extract_country( $reputation );
		$asn     = $this->extract_asn( $reputation );
		if ( '' === $country && 0 === $asn ) {
			return;
		}

		$history = $this->get_history( $user->ID );
		$now     = time();
		$cutoff  = $now - max( 1, (int) get_option( 'reportedip_hive_geo_window_days', 90 ) ) * DAY_IN_SECONDS;

		$history = array_filter(
			$history,
			static function ( $entry ) use ( $cutoff ) {
				return is_array( $entry ) && (int) ( $entry['t'] ?? 0 ) >= $cutoff;
			}
		);

		$known_country = false;
		$known_asn     = false;
		foreach ( $history as $entry ) {
			if ( '' !== $country && ( $entry['country'] ?? '' ) === $country ) {
				$known_country = true;
			}
			if ( 0 !== $asn && (int) ( $entry['asn'] ?? 0 ) === $asn ) {
				$known_asn = true;
			}
		}

		$is_anomaly = ! empty( $history ) && ( ( '' !== $country && ! $known_country ) || ( 0 !== $asn && ! $known_asn ) );

		$history[] = array(
			't'       => $now,
			'country' => $country,
			'asn'     => $asn,
			'ip'      => $ip,
		);
		$history   = array_slice( $history, - self::HISTORY_MAX );
		update_user_meta( $user->ID, self::META_HISTORY, $history );

		if ( ! $is_anomaly ) {
			return;
		}

		$this->log_anomaly( $user, $ip, $country, $asn );
		$this->revoke_trusted_devices( $user->ID );
	}

	/**
	 * Pull cached reputation from the API client. We never trigger a fresh
	 * external call here — the cache is populated during pre-auth check.
	 *
	 * @return array<string,mixed>|array{}
	 */
	private function fetch_reputation( string $ip ): array {
		if ( ! class_exists( 'ReportedIP_Hive_Cache' ) ) {
			return array();
		}
		$cache  = ReportedIP_Hive_Cache::get_instance();
		$cached = $cache->get_reputation( $ip );
		if ( false === $cached ) {
			return array();
		}
		if ( is_array( $cached ) && isset( $cached['data'] ) && is_array( $cached['data'] ) ) {
			return $cached['data'];
		}
		return is_array( $cached ) ? $cached : array();
	}

	private function extract_country( array $reputation ): string {
		foreach ( array( 'countryCode', 'country_code', 'country' ) as $key ) {
			if ( ! empty( $reputation[ $key ] ) && is_string( $reputation[ $key ] ) ) {
				return strtoupper( substr( $reputation[ $key ], 0, 2 ) );
			}
		}
		return '';
	}

	private function extract_asn( array $reputation ): int {
		foreach ( array( 'asn', 'asNumber' ) as $key ) {
			if ( isset( $reputation[ $key ] ) && is_numeric( $reputation[ $key ] ) ) {
				return (int) $reputation[ $key ];
			}
		}
		return 0;
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private function get_history( int $user_id ): array {
		$raw = get_user_meta( $user_id, self::META_HISTORY, true );
		return is_array( $raw ) ? $raw : array();
	}

	private function log_anomaly( WP_User $user, string $ip, string $country, int $asn ): void {
		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->log_security_event(
			'geo_anomaly_detected',
			$ip,
			array(
				'user_id'     => $user->ID,
				'new_country' => $country,
				'new_asn'     => $asn,
			),
			'medium'
		);

		$client  = ReportedIP_Hive::get_instance();
		$monitor = $client->get_security_monitor();
		if ( $monitor instanceof ReportedIP_Hive_Security_Monitor && get_option( 'reportedip_hive_geo_report_to_api', false ) ) {
			$monitor->report_security_event(
				$ip,
				'geo_anomaly',
				array(
					'country' => $country,
					'asn'     => $asn,
				)
			);
		}
	}

	/**
	 * Revoke this user's trusted-device cookies so the next login from this
	 * new geo forces a full 2FA challenge. We delete every row in the
	 * trusted_devices table for the user — cheap, safe, and keeps the
	 * surface tiny. Skipped when 2FA isn't enabled at all.
	 */
	private function revoke_trusted_devices( int $user_id ): void {
		if ( ! get_option( 'reportedip_hive_geo_revoke_trusted_devices', true ) ) {
			return;
		}
		global $wpdb;
		$table = $wpdb->prefix . 'reportedip_hive_trusted_devices';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete( $table, array( 'user_id' => $user_id ), array( '%d' ) );
	}
}
