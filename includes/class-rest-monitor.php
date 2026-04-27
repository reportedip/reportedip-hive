<?php
/**
 * REST API Abuse Monitor.
 *
 * Per-IP request-rate detection on `rest_pre_dispatch`. Distinct from the
 * 2FA-specific REST throttle in class-two-factor-rest.php — this one watches
 * the entire REST surface (`/wp-json/*`) and is the layer that catches
 * scrapers, vulnerability scanners, and burst-abuse against expensive
 * endpoints. Two thresholds run in parallel:
 *
 *  - Global threshold: any IP issuing more than N REST requests within the
 *    window is rate-limited and reported.
 *  - Sensitive-endpoint threshold: lower threshold for routes that leak
 *    user data (`/wp/v2/users`) or grant write access — these warrant a
 *    much faster trigger.
 *
 * Bypass list: REST routes the plugin needs for its own admin AJAX-style
 * features (the `reportedip-hive/v1` 2FA challenge endpoints handle their
 * own throttling) plus the standard `oembed` namespace which is hit by
 * legitimate embed previews.
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

class ReportedIP_Hive_REST_Monitor {

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_REST_Monitor|null
	 */
	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'rest_pre_dispatch', array( $this, 'pre_dispatch' ), 5, 3 );
	}

	/**
	 * Pre-dispatch hook. Runs before authentication / capability checks so a
	 * scanner cannot blow through the threshold while triggering 401 chains.
	 *
	 * @param mixed           $result  Existing dispatch result.
	 * @param WP_REST_Server  $server  REST server instance.
	 * @param WP_REST_Request $request The incoming request.
	 * @return mixed                   Original $result, or a WP_Error if blocked.
	 */
	public function pre_dispatch( $result, $server, $request ) {
		if ( ! get_option( 'reportedip_hive_monitor_rest_api', true ) ) {
			return $result;
		}

		if ( $result instanceof WP_Error ) {
			return $result;
		}

		if ( ! ( $request instanceof WP_REST_Request ) ) {
			return $result;
		}

		/*
		 * Skip the global rate-limit for authenticated users. The Block Editor
		 * alone routinely fires 50+ REST calls when an admin opens a page (post
		 * autosave, media library, taxonomy / user lookups, block patterns,
		 * theme.json), which would otherwise trip the default 60/5min threshold
		 * and lock the admin out of their own backend. Authenticated traffic is
		 * not the threat model this sensor exists for — the per-route 2FA-REST
		 * throttle and other auth-aware sensors cover that surface.
		 */
		if ( is_user_logged_in() ) {
			return $result;
		}

		$route = (string) $request->get_route();

		if ( $this->is_route_bypassed( $route ) ) {
			return $result;
		}

		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return $result;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( '' === $ip || 'unknown' === $ip ) {
			return $result;
		}

		$ip_manager = class_exists( 'ReportedIP_Hive_IP_Manager' )
			? ReportedIP_Hive_IP_Manager::get_instance()
			: null;

		if ( $ip_manager && method_exists( $ip_manager, 'is_whitelisted' ) && $ip_manager->is_whitelisted( $ip ) ) {
			return $result;
		}

		if ( $ip_manager && method_exists( $ip_manager, 'is_blocked' ) && $ip_manager->is_blocked( $ip ) ) {
			return new WP_Error(
				'rest_forbidden_ip_blocked',
				__( 'Access denied.', 'reportedip-hive' ),
				array( 'status' => 403 )
			);
		}

		$client  = ReportedIP_Hive::get_instance();
		$monitor = $client->get_security_monitor();
		if ( ! ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) ) {
			return $result;
		}

		$threshold = (int) get_option( 'reportedip_hive_rest_threshold', 60 );
		$timeframe = (int) get_option( 'reportedip_hive_rest_timeframe', 5 );

		if ( $this->is_sensitive_route( $route ) ) {
			$threshold = (int) get_option( 'reportedip_hive_rest_sensitive_threshold', 20 );
			$timeframe = (int) get_option( 'reportedip_hive_rest_sensitive_timeframe', 5 );
		}

		$blocked = $monitor->track_generic_attempt(
			$ip,
			'rest_abuse',
			'rest_abuse',
			$threshold,
			$timeframe,
			array(
				'route'  => $route,
				'method' => (string) $request->get_method(),
			)
		);

		if ( $blocked && $ip_manager && method_exists( $ip_manager, 'is_blocked' ) && $ip_manager->is_blocked( $ip ) ) {
			return new WP_Error(
				'rest_forbidden_ip_blocked',
				__( 'Access denied due to suspicious REST API activity.', 'reportedip-hive' ),
				array( 'status' => 429 )
			);
		}

		return $result;
	}

	/**
	 * Routes that should never be rate-limited:
	 *  - the plugin's own 2FA endpoints (which run their own throttling);
	 *  - the oEmbed discovery endpoint used by legitimate embeds.
	 */
	private function is_route_bypassed( string $route ): bool {
		$bypass = array(
			'/reportedip-hive/v1',
			'/oembed/1.0/embed',
		);
		$bypass = (array) apply_filters( 'reportedip_hive_rest_bypass_routes', $bypass );

		foreach ( $bypass as $prefix ) {
			$prefix = (string) $prefix;
			if ( '' === $prefix ) {
				continue;
			}
			if ( str_starts_with( $route, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Routes that warrant a much lower threshold because they expose user
	 * data (enumeration vector) or grant write access.
	 */
	private function is_sensitive_route( string $route ): bool {
		$sensitive = array(
			'/wp/v2/users',
			'/wp/v2/comments',
		);
		$sensitive = (array) apply_filters( 'reportedip_hive_rest_sensitive_routes', $sensitive );

		foreach ( $sensitive as $prefix ) {
			$prefix = (string) $prefix;
			if ( '' === $prefix ) {
				continue;
			}
			if ( str_starts_with( $route, $prefix ) ) {
				return true;
			}
		}
		return false;
	}
}
