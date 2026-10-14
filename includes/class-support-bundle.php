<?php
/**
 * Support bundle: one machine-readable diagnosis of a site.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.73
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the support bundle: configuration, health, the events that decide
 * whether a visitor was turned away wrongly, and the active blocks.
 *
 * One builder for every channel (the System Status download, WP-CLI and the
 * MainWP bridge), so a support check reads the same shape everywhere.
 * Everything is aggregated in SQL; no channel loads the log into PHP.
 *
 * Nothing secret leaves through it: no API key, no tokens, no user names, no
 * mail addresses, no query strings, and addresses are cut to their network
 * (/24, /48) unless the operator asks for full addresses in the backend.
 *
 * @since 2.1.73
 */
final class ReportedIP_Hive_Support_Bundle {

	/**
	 * Version of the bundle layout. Raise on a removed or renamed key.
	 */
	const SCHEMA = 1;

	/**
	 * Periods offered in the backend, in days.
	 */
	const PERIODS = array( 1, 7, 14, 30 );

	/**
	 * Longest period any channel may ask for, in days.
	 */
	const MAX_DAYS = 30;

	/**
	 * Most raw events a bundle carries.
	 */
	const MAX_EVENTS = 2000;

	/**
	 * Event types whose raw rows are worth reading one by one: the ones that
	 * turn a visitor away, and the ones that say the plugin itself is unwell.
	 */
	const RECENT_TYPES = array(
		'form_proof_failed',
		'ip_blocked',
		'waf_block',
		'waf_would_block',
		'bot_exemption_denied',
		'verified_bot_block_averted',
		'own_server_ip_block_averted',
		'failed_login',
		'password_spray_threshold_exceeded',
		'disposable_email',
		'comment_spam',
		'blocked_by_reputation',
		'hide_login_block',
		'admin_guest_denied',
		'api_health_degraded',
		'api_call_failed',
		'api_error',
		'api_rate_limited',
		'mail_relay_fallback',
		'mail_relay_error',
	);

	/**
	 * Detail keys a raw event may carry into the bundle. Everything else in
	 * the stored JSON stays on the site.
	 */
	const DETAIL_KEYS = array(
		'event_type',
		'trigger_event',
		'reason',
		'verdict',
		'surface',
		'seconds',
		'rule',
		'group',
		'target',
		'matched',
		'matched_target',
		'ajax_action',
		'source',
		'paranoia',
		'method',
		'request_path',
		'path',
		'duration_minutes',
		'block_type',
		'verifier_state',
		'category',
		'domain',
		'action',
		'attempts',
		'threshold',
		'timeframe',
		'status',
		'error',
		'success_rate',
		'recent_calls',
		'user_agent',
	);

	/**
	 * Build the bundle.
	 *
	 * @param array<string,mixed> $args `days` (1 to 30, default 7), `events`
	 *                                  (raw rows, default 300) and `full_ips`
	 *                                  (bool, default false).
	 * @return array<string,mixed>
	 * @since  2.1.73
	 */
	public static function build( array $args = array() ) {
		$days     = self::clamp( $args['days'] ?? 7, 1, self::MAX_DAYS );
		$events   = self::clamp( $args['events'] ?? 300, 0, self::MAX_EVENTS );
		$full_ips = ! empty( $args['full_ips'] );
		$since    = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		return array(
			'schema'        => self::SCHEMA,
			'generated_at'  => gmdate( 'c' ),
			'period'        => array(
				'days'  => $days,
				'since' => $since,
			),
			'ips'           => $full_ips ? 'full' : 'network',
			'site'          => self::section( array( __CLASS__, 'site' ) ),
			'config'        => self::section( array( __CLASS__, 'config' ) ),
			'health'        => self::section( array( __CLASS__, 'health' ) ),
			'events'        => self::section(
				static function () use ( $since, $events, $full_ips ) {
					return self::events( $since, $events, $full_ips );
				}
			),
			'blocks_active' => self::section(
				static function () use ( $full_ips ) {
					return self::blocks( $full_ips );
				}
			),
			'php_errors'    => self::section( array( __CLASS__, 'php_errors' ) ),
		);
	}

	/**
	 * Note who pulled a bundle through which channel.
	 *
	 * @param string $channel `admin`, `cli` or `mainwp`.
	 * @return void
	 * @since  2.1.73
	 */
	public static function log_generated( $channel ) {
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}
		$logger = ReportedIP_Hive::get_instance()->get_logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'support_bundle_generated',
				'system',
				array(
					'channel' => (string) $channel,
					'user_id' => get_current_user_id(),
				),
				'low'
			);
		}
	}

	/**
	 * Run one section; a failure becomes an `error` entry instead of breaking
	 * the whole bundle.
	 *
	 * @param callable $build Section builder.
	 * @return mixed
	 */
	private static function section( callable $build ) {
		try {
			return call_user_func( $build );
		} catch ( \Throwable $e ) {
			return array( 'error' => get_class( $e ) . ': ' . substr( $e->getMessage(), 0, 200 ) );
		}
	}

	/**
	 * An integer inside a range.
	 *
	 * @param mixed $value Raw value.
	 * @param int   $min   Lowest allowed value.
	 * @param int   $max   Highest allowed value.
	 * @return int
	 */
	private static function clamp( $value, $min, $max ) {
		return max( $min, min( $max, (int) $value ) );
	}

	/**
	 * Where the plugin runs.
	 *
	 * @return array<string,mixed>
	 */
	private static function site() {
		global $wp_version;

		return array(
			'host'       => (string) wp_parse_url( home_url(), PHP_URL_HOST ),
			'home_url'   => home_url( '/' ),
			'multisite'  => is_multisite(),
			'blog_count' => is_multisite() ? (int) get_blog_count() : 1,
			'wp'         => (string) $wp_version,
			'php'        => PHP_VERSION,
			'server'     => isset( $_SERVER['SERVER_SOFTWARE'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ), 0, 60 ) : '',
			'timezone'   => wp_timezone_string(),
			'locale'     => get_locale(),
			'hive'       => REPORTEDIP_HIVE_VERSION,
			'db_version' => (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_db_version', 0 ),
		);
	}

	/**
	 * What is switched on, and how the client address is read.
	 *
	 * @return array<string,mixed>
	 */
	private static function config() {
		$mode = ReportedIP_Hive_Mode_Manager::get_instance();

		$config = array(
			'mode'                 => (string) $mode->get_mode(),
			'tier'                 => (string) $mode->get_current_tier(),
			'report_only'          => (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ),
			'proxy'                => self::proxy(),
			'dropin'               => self::dropin(),
			'form_proof'           => self::form_proof(),
			'settings_non_default' => self::non_default_settings(),
		);

		return $config;
	}

	/**
	 * How this very request resolved its client address. A site whose every
	 * visitor resolves to a proxy address reads its header wrongly.
	 *
	 * @return array<string,mixed>
	 */
	private static function proxy() {
		$header = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' );
		$ranges = class_exists( 'ReportedIP_Hive_Proxy_Trust' )
			? ReportedIP_Hive_Proxy_Trust::parse_ranges( (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_proxy_ranges', '' ) )
			: array();
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$client = class_exists( 'ReportedIP_Hive' ) ? (string) ReportedIP_Hive::get_client_ip() : '';

		return array(
			'header'         => $header,
			'ranges_count'   => count( $ranges ),
			'header_present' => '' !== $header && isset( $_SERVER[ $header ] ),
			'remote_network' => self::network( $remote ),
			'client_network' => self::network( $client ),
			'own_server'     => '' !== $client && class_exists( 'ReportedIP_Hive' ) && ReportedIP_Hive::is_own_server_ip( $client ),
		);
	}

	/**
	 * State of the pre-WordPress guard.
	 *
	 * @return array<string,mixed>
	 */
	private static function dropin() {
		if ( ! class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
			return array( 'available' => false );
		}

		$dropin = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();

		return array(
			'enabled'        => (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ),
			'running'        => (bool) $dropin->is_running(),
			'server'         => (string) $dropin->detect_server(),
			'auto'           => (bool) $dropin->supports_auto_install(),
			'queue_writable' => (bool) $dropin->queue_is_writable(),
		);
	}

	/**
	 * Which forms carry the execution proof.
	 *
	 * @return array<string,mixed>
	 */
	private static function form_proof() {
		$detected = array();
		$active   = array();

		if ( class_exists( 'ReportedIP_Hive_Form_Adapters' ) ) {
			$adapters = ReportedIP_Hive_Form_Adapters::get_instance();
			foreach ( array_keys( ReportedIP_Hive_Form_Adapters::adapters() ) as $slug ) {
				if ( $adapters->detected( $slug ) ) {
					$detected[] = $slug;
				}
				if ( $adapters->active( $slug ) ) {
					$active[] = $slug;
				}
			}
		}

		$since = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_form_adapters_since', 0 );

		return array(
			'enabled'         => (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_form_proof_enabled', true ),
			'pow'             => class_exists( 'ReportedIP_Hive_Form_Proof' ) && ReportedIP_Hive_Form_Proof::computation_owned() && (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_form_proof_pow', true ),
			'detected'        => $detected,
			'active'          => $active,
			'adapters_since'  => $since > 0 ? gmdate( 'c', $since ) : '',
			'disposable_mail' => (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_disposable_email_forms', 'block' ),
		);
	}

	/**
	 * Registry settings that differ from their default. The registry holds no
	 * credential (the API key and the connection identity stay outside it),
	 * so nothing secret is in reach here.
	 *
	 * @return array<string,mixed>
	 */
	private static function non_default_settings() {
		if ( ! class_exists( 'ReportedIP_Hive_Settings_Registry' ) || ! class_exists( 'ReportedIP_Hive_Defaults' ) ) {
			return array();
		}

		$defaults = ReportedIP_Hive_Defaults::all_option_defaults();
		$out      = array();

		foreach ( array_keys( ReportedIP_Hive_Settings_Registry::spec() ) as $key ) {
			$value = ReportedIP_Hive_Settings_Registry::normalize_value( $key, ReportedIP_Hive_Option_Routing::get( $key, $defaults[ $key ] ?? null ) );

			if ( array_key_exists( $key, $defaults ) && wp_json_encode( $value ) === wp_json_encode( ReportedIP_Hive_Settings_Registry::normalize_value( $key, $defaults[ $key ] ) ) ) {
				continue;
			}
			if ( is_string( $value ) && strlen( $value ) > 300 ) {
				$value = substr( $value, 0, 300 ) . ' (' . strlen( $value ) . ' chars)';
			}

			$out[ str_replace( 'reportedip_hive_', '', $key ) ] = $value;
		}

		return $out;
	}

	/**
	 * Readiness, cron, API, report queue and relay quota.
	 *
	 * @return array<string,mixed>
	 */
	private static function health() {
		$readiness = array();
		if ( class_exists( 'ReportedIP_Hive_Readiness' ) ) {
			foreach ( ReportedIP_Hive_Readiness::open_issues( true ) as $issue ) {
				$readiness[] = array(
					'key'      => (string) ( $issue['key'] ?? '' ),
					'severity' => (string) ( $issue['severity'] ?? '' ),
					'since'    => isset( $issue['first_seen'] ) ? gmdate( 'c', (int) $issue['first_seen'] ) : '',
				);
			}
		}

		$cron  = array();
		$hooks = class_exists( 'ReportedIP_Hive_Cron_Handler' ) ? ReportedIP_Hive_Cron_Handler::get_hook_names() : array( 'reportedip_hive_cleanup', 'reportedip_hive_sync_reputation', 'reportedip_hive_process_queue', 'reportedip_hive_refresh_quota', 'reportedip_hive_sync_rulesets' );
		foreach ( $hooks as $hook ) {
			$next   = wp_next_scheduled( $hook );
			$cron[] = array(
				'hook'    => str_replace( 'reportedip_hive_', '', $hook ),
				'next'    => $next ? gmdate( 'c', (int) $next ) : '',
				'overdue' => $next ? max( 0, time() - (int) $next ) : null,
			);
		}

		$stats = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
		$stats = is_array( $stats ) ? $stats : array();

		return array(
			'readiness'        => $readiness,
			'cron'             => $cron,
			'wp_cron_disabled' => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'api'              => array(
				'success_rate'        => $stats['success_rate'] ?? null,
				'recent_success_rate' => $stats['recent_success_rate'] ?? null,
				'total_calls'         => $stats['total_calls'] ?? null,
				'error_types'         => $stats['error_types'] ?? array(),
			),
			'queue'            => self::queue(),
		);
	}

	/**
	 * Report queue counts and what the failed rows say.
	 *
	 * @return array<string,mixed>
	 */
	private static function queue() {
		global $wpdb;

		$table = $wpdb->base_prefix . 'reportedip_hive_api_queue';
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from base_prefix; aggregate read for the support bundle.
		$counts = (array) $wpdb->get_results( "SELECT status, COUNT(*) AS n, MIN(created_at) AS oldest FROM {$table} GROUP BY status", ARRAY_A );
		$errors = (array) $wpdb->get_results( "SELECT LEFT(error_message, 160) AS message, COUNT(*) AS n FROM {$table} WHERE status = 'failed' GROUP BY LEFT(error_message, 160) ORDER BY n DESC LIMIT 10", ARRAY_A );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = array( 'by_status' => array() );
		foreach ( $counts as $row ) {
			$out['by_status'][ (string) $row['status'] ] = array(
				'count'  => (int) $row['n'],
				'oldest' => (string) $row['oldest'],
			);
		}
		$out['failed_errors'] = array_map(
			static function ( $row ) {
				return array(
					'message' => self::scrub( (string) $row['message'] ),
					'count'   => (int) $row['n'],
				);
			},
			$errors
		);

		return $out;
	}

	/**
	 * Event aggregates over the period plus the latest rows of the types
	 * that matter for a false positive.
	 *
	 * @param string $since    UTC datetime the period starts at.
	 * @param int    $limit    Raw rows to include.
	 * @param bool   $full_ips Keep full addresses.
	 * @return array<string,mixed>
	 */
	private static function events( $since, $limit, $full_ips ) {
		global $wpdb;

		$table = $wpdb->base_prefix . 'reportedip_hive_logs';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from base_prefix; every value is bound, the IN() list is one %s per type.
		$by_type = (array) $wpdb->get_results( $wpdb->prepare( "SELECT event_type AS type, severity, COUNT(*) AS n FROM {$table} WHERE created_at >= %s GROUP BY event_type, severity ORDER BY n DESC", $since ), ARRAY_A );
		$by_day  = (array) $wpdb->get_results( $wpdb->prepare( "SELECT DATE(created_at) AS day, event_type AS type, COUNT(*) AS n FROM {$table} WHERE created_at >= %s GROUP BY DATE(created_at), event_type ORDER BY day ASC, n DESC", $since ), ARRAY_A );
		$window  = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(*) AS total, MIN(created_at) AS first_at, MAX(created_at) AS last_at FROM {$table} WHERE created_at >= %s", $since ), ARRAY_A );

		$recent = array();
		if ( $limit > 0 ) {
			$in     = implode( ',', array_fill( 0, count( self::RECENT_TYPES ), '%s' ) );
			$params = array_merge( self::RECENT_TYPES, array( $since, $limit ) );
			$rows   = (array) $wpdb->get_results( $wpdb->prepare( "SELECT created_at, event_type, severity, ip_address, details, blog_id FROM {$table} WHERE event_type IN ($in) AND created_at >= %s ORDER BY id DESC LIMIT %d", $params ), ARRAY_A );
			foreach ( $rows as $row ) {
				$recent[] = self::event_row( $row, $full_ips );
			}
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return array(
			'window'          => array(
				'total' => (int) ( $window['total'] ?? 0 ),
				'first' => (string) ( $window['first_at'] ?? '' ),
				'last'  => (string) ( $window['last_at'] ?? '' ),
			),
			'by_type'         => array_map(
				static function ( $row ) {
					return array(
						'type'     => (string) $row['type'],
						'severity' => (string) $row['severity'],
						'count'    => (int) $row['n'],
					);
				},
				$by_type
			),
			'by_day'          => array_map(
				static function ( $row ) {
					return array(
						'day'   => (string) $row['day'],
						'type'  => (string) $row['type'],
						'count' => (int) $row['n'],
					);
				},
				$by_day
			),
			'summary'         => self::summarize( $recent ),
			'recent'          => $recent,
			'recent_types'    => self::RECENT_TYPES,
			'recent_complete' => count( $recent ) < $limit,
		);
	}

	/**
	 * One raw event, scrubbed.
	 *
	 * @param array<string,mixed> $row      Log row.
	 * @param bool                $full_ips Keep full addresses.
	 * @return array<string,mixed>
	 */
	private static function event_row( array $row, $full_ips ) {
		$details = json_decode( (string) $row['details'], true );
		$details = is_array( $details ) ? $details : array();
		$kept    = array();

		foreach ( self::DETAIL_KEYS as $key ) {
			if ( ! array_key_exists( $key, $details ) ) {
				continue;
			}
			$value = $details[ $key ];
			if ( is_array( $value ) || is_object( $value ) ) {
				$value = wp_json_encode( $value );
			}
			$value = (string) $value;
			if ( in_array( $key, array( 'request_path', 'path' ), true ) ) {
				$value = self::path_only( $value );
			}
			$kept[ $key ] = self::scrub( substr( $value, 0, 'user_agent' === $key ? 120 : 200 ) );
		}

		if ( isset( $details['uri'] ) && ! isset( $kept['path'] ) ) {
			$kept['path'] = self::path_only( (string) $details['uri'] );
		}

		return array(
			'at'       => (string) $row['created_at'],
			'type'     => (string) $row['event_type'],
			'severity' => (string) $row['severity'],
			'ip'       => $full_ips ? (string) $row['ip_address'] : self::network( (string) $row['ip_address'] ),
			'blog_id'  => (int) $row['blog_id'],
			'details'  => $kept,
		);
	}

	/**
	 * Counts over the raw rows that answer the usual support questions in one
	 * glance: which form refusals, which firewall rules, which block triggers.
	 *
	 * @param array<int,array<string,mixed>> $recent Scrubbed raw rows.
	 * @return array<string,mixed>
	 */
	public static function summarize( array $recent ) {
		$count = static function ( array $rows, callable $key ) {
			$out = array();
			foreach ( $rows as $row ) {
				$k         = (string) call_user_func( $key, $row );
				$out[ $k ] = ( $out[ $k ] ?? 0 ) + 1;
			}
			arsort( $out );
			return array_slice( $out, 0, 25, true );
		};

		$of = static function ( $type ) use ( $recent ) {
			return array_values(
				array_filter(
					$recent,
					static function ( $row ) use ( $type ) {
						return $type === $row['type'];
					}
				)
			);
		};

		$form  = $of( 'form_proof_failed' );
		$waf   = $of( 'waf_block' );
		$block = $of( 'ip_blocked' );

		return array(
			'form_proof'  => $count(
				$form,
				static function ( $r ) {
					return ( $r['details']['surface'] ?? '?' ) . ' | ' . ( $r['details']['verdict'] ?? '-' ) . ' | ' . ( $r['details']['reason'] ?? '-' ) . ' | ' . ( $r['details']['request_path'] ?? $r['details']['path'] ?? '' );
				}
			),
			'waf_rules'   => $count(
				$waf,
				static function ( $r ) {
					return ( $r['details']['rule'] ?? '?' ) . ' | ' . ( $r['details']['source'] ?? 'engine' );
				}
			),
			'waf_paths'   => $count(
				$waf,
				static function ( $r ) {
					$path = $r['details']['path'] ?? '';

					return isset( $r['details']['ajax_action'] ) ? $path . ' | ' . $r['details']['ajax_action'] : $path;
				}
			),
			'block_cause' => $count(
				$block,
				static function ( $r ) {
					return ( $r['details']['trigger_event'] ?? $r['details']['reason'] ?? '?' ) . ' | ' . ( $r['details']['duration_minutes'] ?? '?' ) . ' min';
				}
			),
			'networks'    => $count(
				$recent,
				static function ( $r ) {
					return $r['type'] . ' | ' . $r['ip'];
				}
			),
		);
	}

	/**
	 * Active blocks by type plus the newest twenty.
	 *
	 * @param bool $full_ips Keep full addresses.
	 * @return array<string,mixed>
	 */
	private static function blocks( $full_ips ) {
		global $wpdb;

		$table = $wpdb->base_prefix . 'reportedip_hive_blocked';
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from base_prefix; aggregate read for the support bundle.
		$by_type = (array) $wpdb->get_results( "SELECT block_type, COUNT(*) AS n FROM {$table} WHERE is_active = 1 AND ( blocked_until IS NULL OR blocked_until > UTC_TIMESTAMP() ) GROUP BY block_type", ARRAY_A );
		$sample  = (array) $wpdb->get_results( "SELECT ip_address, block_type, reason, blocked_until, created_at FROM {$table} WHERE is_active = 1 AND ( blocked_until IS NULL OR blocked_until > UTC_TIMESTAMP() ) ORDER BY id DESC LIMIT 20", ARRAY_A );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$types = array();
		foreach ( $by_type as $row ) {
			$types[ (string) $row['block_type'] ] = (int) $row['n'];
		}

		return array(
			'by_type' => $types,
			'newest'  => array_map(
				static function ( $row ) use ( $full_ips ) {
					return array(
						'ip'     => $full_ips ? (string) $row['ip_address'] : self::network( (string) $row['ip_address'] ),
						'type'   => (string) $row['block_type'],
						'reason' => self::scrub( substr( (string) $row['reason'], 0, 160 ) ),
						'until'  => (string) $row['blocked_until'],
						'since'  => (string) $row['created_at'],
					);
				},
				$sample
			),
		);
	}

	/**
	 * The last plugin lines of the debug log, when there is one to read.
	 *
	 * @return array<string,mixed>
	 */
	private static function php_errors() {
		$setting = defined( 'WP_DEBUG_LOG' ) ? constant( 'WP_DEBUG_LOG' ) : false;
		$file    = '';
		if ( is_string( $setting ) && '' !== $setting ) {
			$file = $setting;
		} elseif ( $setting ) {
			$file = WP_CONTENT_DIR . '/debug.log';
		}

		if ( '' === $file || ! is_readable( $file ) ) {
			return array( 'available' => false );
		}

		$size   = (int) filesize( $file );
		$handle = fopen( $file, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Reads the tail of the local debug log.
		if ( ! $handle ) {
			return array( 'available' => false );
		}
		fseek( $handle, max( 0, $size - 524288 ) );
		$tail = (string) stream_get_contents( $handle );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closes the handle opened above.

		$lines = array();
		foreach ( explode( "\n", $tail ) as $line ) {
			if ( false !== stripos( $line, 'reportedip' ) ) {
				$lines[] = self::scrub( substr( $line, 0, 300 ) );
			}
		}

		return array(
			'available' => true,
			'lines'     => array_slice( $lines, -50 ),
		);
	}

	/**
	 * Cut an address to its network: /24 for IPv4, /48 for IPv6. Enough to
	 * tell a data centre, a CDN edge and a home line apart, not enough to
	 * point at a person.
	 *
	 * @param string $ip Address.
	 * @return string
	 * @since  2.1.73
	 */
	public static function network( $ip ) {
		$ip = trim( (string) $ip );

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = inet_pton( $ip );
			if ( false !== $packed ) {
				$net = inet_ntop( substr( $packed, 0, 6 ) . str_repeat( "\0", 10 ) );
				return ( false !== $net ? $net : '' ) . '/48';
			}
		}

		return '' === $ip ? '' : 'other';
	}

	/**
	 * A path without its query string or fragment.
	 *
	 * @param string $uri Path or URI.
	 * @return string
	 * @since  2.1.73
	 */
	public static function path_only( $uri ) {
		$path = (string) wp_parse_url( (string) $uri, PHP_URL_PATH );

		return '' !== $path ? $path : '/';
	}

	/**
	 * Remove what may identify a person from free text: mail addresses and
	 * query strings.
	 *
	 * @param string $text Text.
	 * @return string
	 * @since  2.1.73
	 */
	public static function scrub( $text ) {
		$text = (string) preg_replace( '/[A-Z0-9._%+\-]+@([A-Z0-9.\-]+\.[A-Z]{2,})/i', '***@$1', (string) $text );

		return (string) preg_replace( '/\?[^\s"\']*/', '?...', $text );
	}
}
