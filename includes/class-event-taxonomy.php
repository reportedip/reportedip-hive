<?php
/**
 * Security event taxonomy — maps raw event types to display families.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.13
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Canonical mapping of `event_type` strings to threat families.
 *
 * Single source of truth for every dashboard visualisation and the
 * "Recent Activity" stream: it folds the ~40 distinct event types written by
 * the twelve sensors, the WAF and the 2FA suite into seven human-readable
 * families. Operational / informational events (block decisions, API reporting,
 * notifications) map to `null` and are excluded from every threat chart so the
 * numbers reflect attacks, not bookkeeping.
 *
 * @since 2.1.13
 */
class ReportedIP_Hive_Event_Taxonomy {

	/**
	 * Base event type (without the `_threshold_exceeded` suffix) → family key.
	 *
	 * @var array<string, string>
	 */
	private const MAP = array(
		'failed_login'                => 'login',
		'password_spray'              => 'login',
		'wc_login_failed'             => 'login',
		'app_password_abuse'          => 'login',
		'app_password_failed'         => 'login',
		'2fa_brute_force'             => 'login',

		'waf_block'                   => 'firewall',
		'waf_would_block'             => 'firewall',

		'scan_404'                    => 'scanner',
		'decoy_pathblock_hit'         => 'scanner',
		'admin_scanning'              => 'scanner',

		'fake_bot'                    => 'bot',
		'fake_bot_blocked'            => 'bot',

		'user_enumeration'            => 'recon',
		'rest_abuse'                  => 'recon',

		'comment_spam'                => 'spam',
		'comment_honeypot'            => 'spam',
		'xmlrpc_abuse'                => 'spam',
		'disposable_email'            => 'spam',

		'geo_anomaly'                 => 'anomaly',
		'hardening_mode_activated'    => 'anomaly',
		'coordinated_attack_detected' => 'anomaly',
		'reputation_threat'           => 'anomaly',
	);

	/**
	 * Ordered family keys for stable display ordering.
	 *
	 * @var array<int, string>
	 */
	private const ORDER = array( 'login', 'firewall', 'scanner', 'bot', 'recon', 'spam', 'anomaly' );

	/**
	 * Ordered list of threat families with translated labels.
	 *
	 * @return array<string, string> Map of family key to display label.
	 * @since  2.1.13
	 */
	public static function labels() {
		$labels = array(
			'login'    => __( 'Login & Credential', 'reportedip-hive' ),
			'firewall' => __( 'Firewall (WAF)', 'reportedip-hive' ),
			'scanner'  => __( 'Scanners & Probes', 'reportedip-hive' ),
			'bot'      => __( 'Fake Bots', 'reportedip-hive' ),
			'recon'    => __( 'Recon & Enumeration', 'reportedip-hive' ),
			'spam'     => __( 'Spam & Flooding', 'reportedip-hive' ),
			'anomaly'  => __( 'Anomalies', 'reportedip-hive' ),
		);

		$ordered = array();
		foreach ( self::ORDER as $key ) {
			$ordered[ $key ] = $labels[ $key ];
		}
		return $ordered;
	}

	/**
	 * Resolve a single family label.
	 *
	 * @param string $key Family key.
	 * @return string Translated label, or the key itself when unknown.
	 * @since  2.1.13
	 */
	public static function label_for( $key ) {
		$labels = self::labels();
		return $labels[ $key ] ?? (string) $key;
	}

	/**
	 * All event types that belong to a threat family.
	 *
	 * Returns every mapped base type plus its generated `_threshold_exceeded`
	 * variant, suitable for an SQL `IN()` filter that selects only attack rows
	 * (variants that never occur are harmless in the clause).
	 *
	 * @return string[] Distinct threat event-type strings.
	 * @since  2.1.13
	 */
	public static function threat_event_types() {
		$types = array();
		foreach ( array_keys( self::MAP ) as $base ) {
			$types[] = $base;
			$types[] = $base . '_threshold_exceeded';
		}
		return array_values( array_unique( $types ) );
	}

	/**
	 * Map a raw event type to its threat family.
	 *
	 * Strips the generated `_threshold_exceeded` suffix before the lookup so
	 * both the base event and its threshold variant resolve to one family.
	 *
	 * @param string $event_type Raw event type from the logs table.
	 * @return string|null Family key, or null for operational/non-threat events.
	 * @since  2.1.13
	 */
	public static function classify( $event_type ) {
		$type = (string) $event_type;

		$suffix = '_threshold_exceeded';
		if ( substr( $type, -strlen( $suffix ) ) === $suffix ) {
			$type = substr( $type, 0, -strlen( $suffix ) );
		}

		return self::MAP[ $type ] ?? null;
	}
}
