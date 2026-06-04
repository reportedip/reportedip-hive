<?php
/**
 * Decoy-Path-Block — single-request detection of hits to known bait paths.
 *
 * Distinct from {@see ReportedIP_Hive_Scan_Detector} which counts honeypath
 * 404s in an N-of-Y window: this sensor reacts on the **first** hit to a path
 * that legitimate visitors never request (e.g. `/.env.backup`,
 * `/wp-config.old.php`). The hit is logged at severity `high` and forwarded
 * to the Hive community-reputation queue. The visitor itself sees a 403, but
 * the source IP is NOT added to the local block table — false-positives from
 * legitimate backup plugins / admin tests would otherwise lock the site out
 * of its own traffic for 24 h. The companion class
 * {@see ReportedIP_Hive_Decoy_Htaccess_Writer} keeps an Apache rewrite block
 * in the site's `.htaccess` so that real bait files on disk (`.env.backup`
 * left behind by a developer, etc.) are routed through WordPress instead of
 * being served directly — security and detection in one move.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
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
		'/.env.orig',
		'/.env.production.bak',
		'/.env.local.bak',
		'/wp-config.php.bak',
		'/wp-config.php.old',
		'/wp-config.php.save',
		'/wp-config.php.orig',
		'/wp-config.php.swp',
		'/wp-config.php~',
		'/wp-config.bak',
		'/wp-config.bak.php',
		'/wp-config.old.php',
		'/wp-config.save.php',
		'/wp-config.backup.php',
		'/configuration.php.bak',
		'/db-dump-master.sql.php',
		'/database-dump.sql',
		'/backup-db.sql.php',
		'/dump.sql',
		'/database.sql',
		'/backup.sql',
		'/db.sql',
		'/admin-shell-console.php',
		'/debug-logs-temp.php',
		'/admin-ajax.php.bak',
		'/sftp-config.json',
		'/web.config.bak',
		'/.htpasswd',
		'/.htaccess.bak',
		'/.aws/credentials',
		'/.aws/config',
		'/.ssh/id_rsa',
		'/.ssh/authorized_keys',
		'/id_rsa',
		'/private.key',
		'/server.key',
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
	 * and fragment are stripped). Trailing slashes are ignored. On Multisite
	 * subdir installs a request to `/site-a/.env.backup` must match the same
	 * bait as `/.env.backup`, so any decoy entry is also accepted as a
	 * suffix as long as the leading remainder is a single subdir segment
	 * (`[_0-9a-zA-Z-]+`). That mirrors the optional capture group in the
	 * `.htaccess` / nginx snippets and keeps PHP detection and server-level
	 * rewrites consistent.
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
		foreach ( $paths as $entry ) {
			$needle  = '/' . ltrim( $entry, '/' );
			$end_pos = strlen( $only_path ) - strlen( $needle );
			if ( $end_pos <= 0 ) {
				continue;
			}
			if ( substr( $only_path, $end_pos ) !== $needle ) {
				continue;
			}
			$prefix = substr( $only_path, 0, $end_pos );
			if ( '' === $prefix || preg_match( '#^/[_0-9a-zA-Z-]+$#', $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * `init` priority-1 handler — checks the current request URI against the
	 * decoy list, logs the hit (which forwards to the community queue) and
	 * emits a per-request 403 response. The source IP is NOT added to the
	 * local block table.
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

		$path_only = wp_parse_url( $uri, PHP_URL_PATH );
		$path_only = is_string( $path_only ) ? strtolower( rtrim( $path_only, '/' ) ) : '';

		$htaccess_handled = class_exists( 'ReportedIP_Hive_Decoy_Htaccess_Writer' )
			&& ReportedIP_Hive_Decoy_Htaccess_Writer::get_instance()->is_block_present();

		$details = array(
			'path'             => $path_only,
			'htaccess_handled' => $htaccess_handled,
			'user_agent'       => isset( $_SERVER['HTTP_USER_AGENT'] )
				? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, REPORTEDIP_USER_AGENT_MAX_LENGTH )
				: '',
		);

		ReportedIP_Hive_Logger::get_instance()->log_security_event( 'decoy_pathblock_hit', $ip, $details, 'high' );

		$hive = ReportedIP_Hive::get_instance();
		if ( method_exists( $hive, 'get_security_monitor' ) ) {
			$monitor = $hive->get_security_monitor();
			if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
				$monitor->report_security_event( $ip, 'decoy_pathblock_hit', $details );
			}
		}

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
	 * Build the inner directive lines for the Apache rewrite block (without
	 * `# BEGIN` / `# END` markers — `insert_with_markers()` supplies those).
	 *
	 * The rewrite routes matching requests to `index.php` so WordPress and the
	 * Hive sensor are loaded — direct `[F,L]` would skip PHP and silence both
	 * the local log and the community report.
	 *
	 * @return string[] Apache directive lines.
	 */
	public static function htaccess_block_lines() {
		$alternation = self::path_alternation();
		$lines       = array();
		$lines[]     = '<IfModule mod_rewrite.c>';
		$lines[]     = '    RewriteEngine On';
		$lines[]     = '    RewriteCond %{REQUEST_URI} ^(/[_0-9a-zA-Z-]+)?/(' . $alternation . ')$ [NC]';
		$lines[]     = '    RewriteRule ^ /index.php [L,QSA]';
		$lines[]     = '</IfModule>';
		return $lines;
	}

	/**
	 * Apache/.htaccess snippet as plain text for the Settings UI preview and
	 * as Copy-Paste fallback when the file is not writable.
	 *
	 * @return string
	 */
	public static function htaccess_snippet() {
		$lines = array( '# ReportedIP Hive — Decoy path detection (Apache)' );
		$lines = array_merge( $lines, self::htaccess_block_lines() );
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * nginx regex snippet for paste into the site's `server { ... }` block.
	 *
	 * Works on plain nginx and on managed stacks that put the
	 * `{custom_directives}` placeholder BEFORE the default `location ~ /\.
	 * { deny all; }` deny rule. On stacks that emit custom directives AFTER
	 * the dot-file deny (most ISPConfig templates do), the deny rule wins on
	 * regex-priority and this snippet is silently shadowed — use
	 * {@see self::nginx_snippet_exact_match()} there instead.
	 *
	 * @return string
	 */
	public static function nginx_snippet() {
		$alternation = self::path_alternation();
		$lines       = array();
		$lines[]     = '# ReportedIP Hive — Decoy path detection (nginx, paste into your server { ... } block)';
		$lines[]     = 'location ~* ^(/[_0-9a-zA-Z-]+)?/(' . $alternation . ')$ {';
		$lines[]     = '    rewrite ^ /index.php last;';
		$lines[]     = '}';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * nginx exact-match snippet — one `location = /<bait>` line per default
	 * path. Exact-match locations have higher priority than any regex
	 * location, so this variant survives even when a `location ~ /\. { deny
	 * all; }` is configured first by the host template (the typical
	 * ISPConfig setup). Paste into the "nginx Directives" field of the
	 * site; ISPConfig will reload nginx automatically.
	 *
	 * @return string
	 */
	public static function nginx_snippet_exact_match() {
		$lines   = array();
		$lines[] = '# ReportedIP Hive — Decoy path detection (nginx, exact-match form for ISPConfig/managed stacks)';
		foreach ( self::decoy_paths() as $path ) {
			$lines[] = 'location = ' . $path . ' { rewrite ^ /index.php last; }';
		}
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Build the regex alternation `(\.env\.backup|wp-config\.old\.php|…)` used
	 * by the rewrite-block + nginx regex snippets. Forward slashes inside
	 * nested entries (`.aws/credentials`) are left as-is — they are not
	 * regex metacharacters and apache/nginx parse them literally.
	 *
	 * @return string
	 */
	private static function path_alternation() {
		$escaped = array();
		foreach ( self::decoy_paths() as $path ) {
			$escaped[] = str_replace( '.', '\\.', ltrim( $path, '/' ) );
		}
		return implode( '|', $escaped );
	}
}
