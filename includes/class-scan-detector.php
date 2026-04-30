<?php
/**
 * 404 / Scanner-Pattern Detector.
 *
 * Two layered triggers:
 *
 *  - High-rate 404s (default ≥ 8 within 60 s) catch any scanner that walks
 *    a directory list of "common WP paths" hoping for unprotected files.
 *  - Pattern-based instant trigger: a single hit on one of the known-bad
 *    paths (`/.env`, `/wp-config.php.bak`, `/wp-content/debug.log`, …) is
 *    enough — these never appear in normal traffic.
 *
 * Sensitive paths are configurable via the `reportedip_hive_scan_paths`
 * filter so site operators can add their own honeypot URLs.
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

class ReportedIP_Hive_Scan_Detector {

	/**
	 * Paths that almost always indicate a scanner / vulnerability probe.
	 * One hit is enough to mark the IP. Lower-case match against the
	 * request path (no query string).
	 */
	private const KNOWN_SCAN_PATHS = array(
		'/.env',
		'/.env.local',
		'/.env.production',
		'/.git/config',
		'/.git/head',
		'/wp-config.php.bak',
		'/wp-config.php.old',
		'/wp-config.php~',
		'/wp-config.bak',
		'/wp-config.old',
		'/wp-content/debug.log',
		'/wp-content/uploads/error_log',
		'/wp-content/plugins/akismet/akismet.php.bak',
		'/wp-admin/install.php.bak',
		'/wordpress/wp-config.php',
		'/old/wp-config.php',
		'/backup/wp-config.php',
		'/phpmyadmin/',
		'/pma/',
		'/dbadmin/',
		'/.aws/credentials',
		'/.ssh/id_rsa',
	);

	/**
	 * Path *prefixes* that carry a scanner signature even on 404. We match by
	 * prefix because attackers parametrise the suffix.
	 */
	private const KNOWN_SCAN_PREFIXES = array(
		'/wp-content/plugins/wp-file-manager/',
		'/wp-content/plugins/file-manager/',
		'/wp-content/plugins/ultimate-member/',
		'/cgi-bin/',
		'/.well-known/acme-challenge/.',
	);

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Scan_Detector|null
	 */
	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'template_redirect', array( $this, 'on_template_redirect' ), 999 );
	}

	/**
	 * 404 hook. Runs late so theme-level overrides have already executed —
	 * we only count the request as a scan candidate if WP itself decided to
	 * serve a 404.
	 */
	public function on_template_redirect(): void {
		if ( ! get_option( 'reportedip_hive_monitor_404_scans', true ) ) {
			return;
		}

		$path        = $this->get_request_path();
		$is_scan_hit = $this->is_known_scan_path( $path );

		if ( ! is_404() && ! $is_scan_hit ) {
			return;
		}

		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( '' === $ip || 'unknown' === $ip ) {
			return;
		}

		$ip_manager = class_exists( 'ReportedIP_Hive_IP_Manager' )
			? ReportedIP_Hive_IP_Manager::get_instance()
			: null;
		if ( $ip_manager && method_exists( $ip_manager, 'is_whitelisted' ) && $ip_manager->is_whitelisted( $ip ) ) {
			return;
		}

		/*
		 * Authenticated users can legitimately rack up 404s — missing CSS source
		 * maps, deprecated plugin asset URLs after an update, the WordPress
		 * "page not found" admin search. Don't fire the burst trigger for them.
		 *
		 * Pattern hits (.env, wp-config.php.bak, /.git/config, /phpmyadmin/ …)
		 * stay armed even for logged-in users — those paths have no legitimate
		 * use anywhere, including from an admin's browser.
		 */
		if ( ! $is_scan_hit && is_user_logged_in() ) {
			return;
		}

		$client  = ReportedIP_Hive::get_instance();
		$monitor = $client->get_security_monitor();
		if ( ! ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) ) {
			return;
		}

		$threshold = $is_scan_hit
			? 1
			: (int) get_option( 'reportedip_hive_scan_404_threshold', 8 );
		$timeframe = (int) get_option( 'reportedip_hive_scan_404_timeframe', 1 );

		$monitor->track_generic_attempt(
			$ip,
			'scan_404',
			'scan_404',
			$threshold,
			$timeframe,
			array(
				'path'        => $path,
				'pattern_hit' => $is_scan_hit,
			)
		);
	}

	/**
	 * Lower-case, query-stripped request path.
	 */
	private function get_request_path(): string {
		$raw  = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) )
			: '';
		$path = (string) wp_parse_url( $raw, PHP_URL_PATH );
		return strtolower( $path );
	}

	/**
	 * Whether the request path matches a known scanner signature.
	 */
	private function is_known_scan_path( string $path ): bool {
		$paths    = (array) apply_filters( 'reportedip_hive_scan_paths', self::KNOWN_SCAN_PATHS );
		$prefixes = (array) apply_filters( 'reportedip_hive_scan_prefixes', self::KNOWN_SCAN_PREFIXES );

		if ( in_array( $path, $paths, true ) ) {
			return true;
		}
		foreach ( $prefixes as $prefix ) {
			$prefix = strtolower( (string) $prefix );
			if ( '' !== $prefix && str_starts_with( $path, $prefix ) ) {
				return true;
			}
		}
		return false;
	}
}
