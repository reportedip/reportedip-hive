<?php
/**
 * Decoy-Path-Block — instant ban on single-request hits to known bait paths.
 *
 * Distinct from {@see ReportedIP_Hive_Scan_Detector} which counts honeypath
 * 404s in an N-of-Y window: this sensor blocks on the **first** hit to a path
 * that legitimate visitors never request (e.g. `/.env.backup`,
 * `/wp-config.old.php`). No physical decoy files are dropped on disk — the
 * detection lives entirely in the request pipeline, plus optional
 * `.htaccess` / nginx snippets the admin can copy into their server config
 * for earlier (pre-PHP) blocking.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.9
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Single-request decoy-path block sensor.
 *
 * @since 2.0.9
 */
final class ReportedIP_Hive_Decoy_Path_Block {

	/**
	 * Built-in bait paths. Extended via `reportedip_hive_decoy_paths` filter.
	 *
	 * @var string[]
	 */
	const DEFAULT_PATHS = array(
		'/.env.backup',
		'/.env.old',
		'/.env.bak',
		'/.env.save',
		'/wp-config.old.php',
		'/wp-config.bak.php',
		'/wp-config.save.php',
		'/wp-config.backup.php',
		'/db-dump-master.sql.php',
		'/database-dump.sql',
		'/backup-db.sql.php',
		'/admin-shell-console.php',
		'/debug-logs-temp.php',
		'/admin-ajax.php.bak',
		'/sftp-config.json',
		'/web.config.bak',
	);

	/**
	 * Per-request memo so the hook runs at most once even if `init` fires twice.
	 *
	 * @var bool
	 */
	private $handled = false;

	private static $instance = null;

	/**
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the request-time hook (priority 1, before any other plugin init).
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'init', array( $this, 'maybe_block' ), 1 );
	}

	/**
	 * Merged bait-path list (defaults + filter additions).
	 *
	 * Filter additions are normalized to lowercase with a leading slash so
	 * `/My-App/config.php` and `my-app/config.php` both match the same canonical
	 * `/my-app/config.php`. Result is memoized per request because both the
	 * hot-path matcher and both snippet renderers consult it.
	 *
	 * @return string[]
	 */
	public static function decoy_paths() {
		static $memo = null;
		if ( null !== $memo ) {
			return $memo;
		}
		$extra = apply_filters( 'reportedip_hive_decoy_paths', array() );
		if ( ! is_array( $extra ) ) {
			$extra = array();
		}
		$paths = array_merge( self::DEFAULT_PATHS, $extra );
		$paths = array_filter(
			array_map(
				static function ( $p ) {
					$p = (string) $p;
					if ( '' === $p ) {
						return '';
					}
					if ( '/' !== $p[0] ) {
						$p = '/' . $p;
					}
					return strtolower( $p );
				},
				$paths
			)
		);
		$memo  = array_values( array_unique( $paths ) );
		return $memo;
	}

	/**
	 * Whether the given path matches a configured decoy entry.
	 *
	 * Matches case-insensitively on the URL path component only (query string
	 * and fragment are stripped). Trailing slashes are ignored.
	 *
	 * @param string $path Request path (e.g. `/wp-config.old.php?foo=bar`).
	 * @return bool
	 */
	public static function is_decoy_path( $path ) {
		if ( ! is_string( $path ) || '' === $path ) {
			return false;
		}
		$only_path = wp_parse_url( $path, PHP_URL_PATH );
		if ( ! is_string( $only_path ) || '' === $only_path ) {
			return false;
		}
		$only_path = strtolower( rtrim( $only_path, '/' ) );
		if ( '' === $only_path ) {
			return false;
		}
		$paths = self::decoy_paths();
		if ( in_array( $only_path, $paths, true ) ) {
			return true;
		}
		$basename = '/' . basename( $only_path );
		return in_array( $basename, $paths, true );
	}

	/**
	 * `init` priority-1 handler — checks the current request URI against the
	 * decoy list, blocks the source IP and emits a 403 response.
	 *
	 * @return void
	 */
	public function maybe_block() {
		if ( $this->handled ) {
			return;
		}
		$this->handled = true;

		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_decoy_pathblock_enabled', true ) ) {
			return;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			: '';
		if ( '' === $uri || ! self::is_decoy_path( $uri ) ) {
			return;
		}

		$ip = (string) ReportedIP_Hive::get_instance()->get_client_ip();
		if ( '' === $ip ) {
			return;
		}

		$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
		if ( $ip_manager->is_whitelisted( $ip ) ) {
			return;
		}

		$duration_hours = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_decoy_block_hours', 24 );
		$duration_hours = max( 1, min( 168, $duration_hours ) );

		$path_only = wp_parse_url( $uri, PHP_URL_PATH );
		$path_only = is_string( $path_only ) ? strtolower( rtrim( $path_only, '/' ) ) : '';

		ReportedIP_Hive_Logger::get_instance()->log_security_event(
			'decoy_pathblock_hit',
			$ip,
			array(
				'path'           => $path_only,
				'duration_hours' => $duration_hours,
				'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] )
					? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, REPORTEDIP_USER_AGENT_MAX_LENGTH )
					: '',
			),
			'high'
		);

		$ip_manager->block_ip( $ip, 'decoy_pathblock: ' . $path_only, $duration_hours, 'automatic' );

		if ( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ) {
			return;
		}

		if ( class_exists( 'ReportedIP_Hive' ) ) {
			ReportedIP_Hive::emit_block_response_headers();
		}
		status_header( 403 );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo "Forbidden.\n";
		exit;
	}

	/**
	 * Apache/.htaccess snippet for paste into the site's `.htaccess`. Returns
	 * literal text; the admin UI escapes it for `<pre>` display.
	 *
	 * @return string
	 */
	public static function htaccess_snippet() {
		$lines   = array();
		$lines[] = '# ReportedIP Hive — Decoy path block (Apache, copy into .htaccess)';
		$lines[] = '<IfModule mod_rewrite.c>';
		$lines[] = '    RewriteEngine On';
		foreach ( self::decoy_paths() as $path ) {
			$pattern = ltrim( $path, '/' );
			$pattern = str_replace( '.', '\\.', $pattern );
			$lines[] = '    RewriteRule ^' . $pattern . '$ - [F,L]';
		}
		$lines[] = '</IfModule>';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * nginx snippet for paste into the site's `server { ... }` block.
	 *
	 * @return string
	 */
	public static function nginx_snippet() {
		$paths = array();
		foreach ( self::decoy_paths() as $path ) {
			$paths[] = str_replace( '.', '\\.', ltrim( $path, '/' ) );
		}
		$alternation = implode( '|', $paths );
		$lines       = array();
		$lines[]     = '# ReportedIP Hive — Decoy path block (nginx, paste into your server { ... } block)';
		$lines[]     = 'location ~* ^/(' . $alternation . ')$ {';
		$lines[]     = '    return 403;';
		$lines[]     = '}';
		return implode( "\n", $lines ) . "\n";
	}
}
