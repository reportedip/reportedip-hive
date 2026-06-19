<?php
/**
 * Pre-WordPress WAF drop-in manager.
 *
 * Optional "extended protection" layer: generates a self-contained PHP guard at
 * `wp-content/reportedip-hive-waf.php` and wires it as an `auto_prepend_file`
 * so the active WAF rules run *before* WordPress loads — stopping a malicious
 * request before any other code executes. Modelled on
 * {@see ReportedIP_Hive_Decoy_Htaccess_Writer}: idempotent marker block,
 * `admin_init` self-heal with an hourly lock, writability probe, clean removal
 * on deactivation.
 *
 * Server-aware: Apache (mod_php) gets a `.htaccess` `php_value` directive,
 * PHP-FPM/CGI gets a `.user.ini` directive, and nginx gets a copy-paste snippet
 * (never auto-written). The generated guard is fail-open — any error or missing
 * dependency lets the request through so the drop-in can never take the site
 * down. Removal strips every directive the plugin controls (`.htaccess`,
 * `.user.ini`) and then *neutralises* the guard to an inert stub instead of
 * deleting it: a directive the plugin cannot reach (an nginx `fastcgi_param` or
 * a hand-edited `php.ini` `auto_prepend_file`) would otherwise point at a
 * missing file and fatal every request — the classic "waf-drop-in 500" that
 * locks the admin out of their own site. An always-present, do-nothing stub
 * makes that failure mode structurally impossible. The guard is rebaked
 * immediately (queued once per request on shutdown) when the `waf` ruleset is
 * re-applied or the IP whitelist changes; the hourly self-heal is only the
 * fallback.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages the pre-WordPress WAF drop-in and its server directive.
 *
 * @since 2.1.2
 */
class ReportedIP_Hive_WAF_Dropin_Manager {

	/**
	 * Marker label wrapped by insert_with_markers() as `# BEGIN/END`.
	 */
	const MARKER = 'ReportedIP Hive WAF';

	/**
	 * Hourly self-heal throttle transient.
	 */
	const HEAL_LOCK_TRANSIENT = 'reportedip_hive_waf_dropin_heal';

	/**
	 * Generated guard file name inside wp-content.
	 */
	const PREPEND_FILENAME = 'reportedip-hive-waf.php';

	/**
	 * Generated-guard format version (bump to force a self-heal regenerate).
	 */
	const DROPIN_VERSION = 4;

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_WAF_Dropin_Manager|null
	 */
	private static $instance = null;

	/**
	 * Whether a guard rebake is already queued for this request.
	 *
	 * @var bool
	 */
	private $resync_queued = false;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_WAF_Dropin_Manager
	 * @since  2.1.2
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the toggle hooks and the self-heal.
	 *
	 * @since 2.1.2
	 */
	private function __construct() {
		add_action( 'update_option_' . ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, array( $this, 'on_toggle' ) );
		add_action( 'update_site_option_' . ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, array( $this, 'on_toggle' ) );
		add_action( 'reportedip_hive_ruleset_applied', array( $this, 'on_ruleset_applied' ) );
		add_action( 'reportedip_hive_whitelist_changed', array( $this, 'queue_resync' ) );
		add_action( 'reportedip_hive_waf_exceptions_changed', array( $this, 'queue_resync' ) );
		foreach ( array( ReportedIP_Hive_WAF::OPT_ENABLED, ReportedIP_Hive_WAF::OPT_REPORT_ONLY, ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED ) as $opt ) {
			add_action( 'update_option_' . $opt, array( $this, 'queue_resync' ) );
			add_action( 'update_site_option_' . $opt, array( $this, 'queue_resync' ) );
		}
		add_action( 'admin_init', array( $this, 'maybe_self_heal' ) );
	}

	/**
	 * React to a freshly applied ruleset: only the `waf` ruleset is baked into
	 * the guard, every other key is irrelevant here.
	 *
	 * @param string $key Applied ruleset key.
	 * @return void
	 * @since  2.1.2
	 */
	public function on_ruleset_applied( $key ) {
		if ( 'waf' === $key ) {
			$this->queue_resync();
		}
	}

	/**
	 * Queue a guard rebake on shutdown (at most once per request), so bulk
	 * whitelist actions and multi-ruleset syncs trigger a single regenerate
	 * with the final state instead of one write per change.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function queue_resync() {
		if ( $this->resync_queued ) {
			return;
		}
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) ) {
			return;
		}
		$this->resync_queued = true;
		add_action( 'shutdown', array( $this, 'run_queued_resync' ) );
	}

	/**
	 * Shutdown callback for the queued rebake (void wrapper around sync()).
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function run_queued_resync() {
		$this->sync();
	}

	/**
	 * React to the drop-in toggle changing: sync when on, remove when off.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function on_toggle() {
		if ( (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) ) {
			$this->sync();
		} else {
			$this->remove();
		}
	}

	/**
	 * Re-validate the drop-in at most once an hour (main site only), so a
	 * ruleset change or an externally edited config self-heals.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function maybe_self_heal() {
		if ( ! $this->is_main_site() ) {
			return;
		}
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) ) {
			return;
		}
		if ( get_site_transient( self::HEAL_LOCK_TRANSIENT ) ) {
			return;
		}
		set_site_transient( self::HEAL_LOCK_TRANSIENT, 1, HOUR_IN_SECONDS );
		$this->sync();
	}

	/**
	 * Write the guard file and wire the server directive. When the toggle is
	 * off this delegates to remove(). Network-wide: only the main site touches
	 * the shared server filesystem.
	 *
	 * @return bool True on success.
	 * @since  2.1.2
	 */
	public function sync() {
		if ( ! $this->is_main_site() ) {
			return false;
		}
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) ) {
			return $this->remove();
		}

		$prepend = $this->prepend_path();
		if ( '' === $prepend ) {
			return false;
		}

		$content = $this->generate_prepend();
		if ( false === file_put_contents( $prepend, $content ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Generating a same-host PHP guard outside the plugin dir; WP_Filesystem cannot place an auto_prepend_file target reliably.
			return false;
		}

		$server = $this->detect_server();

		if ( 'apache' === $server ) {
			return $this->write_directive( $this->htaccess_path(), $this->htaccess_lines( $prepend ) );
		}
		if ( 'fpm' === $server ) {
			return $this->write_user_ini_directive( $this->user_ini_path(), $this->user_ini_lines( $prepend ) );
		}

		/*
		 * nginx (and unknown): the guard file exists, but the directive must be
		 * pasted into the server config by hand — the UI surfaces the snippet.
		 */
		return true;
	}

	/**
	 * Remove the drop-in. Strips the directive from BOTH plugin-controlled
	 * targets FIRST, then *neutralises* the guard to an inert stub instead of
	 * deleting it.
	 *
	 * Deleting the guard file is the original sin behind the "waf-drop-in 500":
	 * an nginx `fastcgi_param` or a hand-edited `php.ini auto_prepend_file` line
	 * lives outside everything the plugin can write, so stripping `.htaccess` /
	 * `.user.ini` leaves that pointer in place. A deleted target then fatals
	 * every PHP request — including wp-admin — and the site can only be revived
	 * over FTP/SSH. Leaving a do-nothing stub on disk keeps any such orphaned
	 * pointer harmless: PHP loads an existing file that immediately returns.
	 *
	 * @return bool True (best effort; missing pieces are treated as removed).
	 * @since  2.1.2
	 */
	public function remove() {
		if ( ! $this->is_main_site() ) {
			return false;
		}

		$this->strip_directive( $this->htaccess_path() );
		$this->strip_directive( $this->user_ini_path() );

		return $this->neutralize_guard();
	}

	/**
	 * Overwrite the guard file with an inert stub so a stale `auto_prepend_file`
	 * the plugin cannot reach (nginx / hand-edited php.ini) can never point at a
	 * missing file. A do-nothing-but-present file is always safe; a dangling
	 * pointer is a site-wide 500. Wordfence's `wordfence-waf.php` works the same
	 * way — the prepend target is engineered to be fail-safe, not deleted.
	 *
	 * The stub deliberately does NOT define `REPORTEDIP_HIVE_WAF_DROPIN`, so
	 * {@see is_running()} correctly reports the WAF as inactive afterwards.
	 *
	 * @return bool True on success or when there is nothing to neutralise.
	 * @since  2.1.8
	 */
	private function neutralize_guard() {
		$prepend = $this->prepend_path();
		if ( '' === $prepend ) {
			return true;
		}
		if ( ! file_exists( $prepend ) ) {
			return true;
		}
		$stub = "<?php\n"
			. "/**\n"
			. " * ReportedIP Hive WAF drop-in — DISABLED.\n"
			. " *\n"
			. " * This file is intentionally inert. It is left in place (rather than\n"
			. " * deleted) so a leftover auto_prepend_file directive in php.ini or an\n"
			. " * nginx fastcgi_param cannot point at a missing file and break the site\n"
			. " * with a 500 error. It is safe to delete once no auto_prepend_file points\n"
			. " * here.\n"
			. " */\n"
			. "return;\n";
		return false !== file_put_contents( $prepend, $stub ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Neutralising a same-host auto_prepend_file target; WP_Filesystem cannot reliably write outside the plugin dir.
	}

	/**
	 * Whether the guard directive is currently present in either target file.
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	public function is_active() {
		foreach ( array( $this->htaccess_path(), $this->user_ini_path() ) as $file ) {
			if ( '' !== $file && file_exists( $file ) && is_readable( $file ) ) {
				$contents = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a same-host config file to report status; WP_Filesystem is unavailable on the front end.
				if ( false !== $contents && ( false !== strpos( $contents, '# BEGIN ' . self::MARKER ) || false !== strpos( $contents, '; BEGIN ' . self::MARKER ) ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Whether the guard actually executed for the current request — the
	 * definitive "it works" signal. The guard defines the constant on every PHP
	 * request (including wp-admin), so the admin page itself proves the chain
	 * end to end, regardless of how the directive was installed (auto-written,
	 * nginx snippet or a php.ini edit).
	 *
	 * @return bool
	 * @since  2.1.3
	 */
	public function is_running() {
		return defined( 'REPORTEDIP_HIVE_WAF_DROPIN' );
	}

	/**
	 * Whether the generated guard file exists on disk.
	 *
	 * @return bool
	 * @since  2.1.3
	 */
	public function guard_exists() {
		$path = $this->prepend_path();
		return '' !== $path && file_exists( $path );
	}

	/**
	 * Detected wiring target token (apache|fpm|nginx|unknown).
	 *
	 * The token names the mechanism used to install the directive, NOT the
	 * front-end web server: it decides between `.htaccess` (mod_php),
	 * auto-written `.user.ini` (PHP-FPM/CGI/LiteSpeed) and the hand-pasted
	 * nginx snippet.
	 *
	 * The PHP SAPI is therefore checked BEFORE the SERVER_SOFTWARE string.
	 * Under PHP-FPM — which is how nginx (and most modern Apache) serve PHP —
	 * `auto_prepend_file` in a document-root `.user.ini` is honoured for every
	 * PHP request regardless of the web server's `location` blocks. The manual
	 * nginx snippet, by contrast, only covers the single `location` it is pasted
	 * into, so endpoints handled by their own blocks (wp-login.php, the cached
	 * front controller) silently escape the guard. Preferring `.user.ini`
	 * whenever a FastCGI SAPI is present closes that coverage gap and removes the
	 * manual step. The bare `nginx` token is reserved for the rare nginx stack
	 * without a FastCGI PHP SAPI, where only the snippet can wire the directive.
	 *
	 * @param string|null $sapi Override SAPI (defaults to php_sapi_name()); for tests.
	 * @return string
	 * @since  2.1.2
	 */
	public function detect_server( $sapi = null ) {
		$sapi     = null === $sapi ? php_sapi_name() : (string) $sapi;
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Lower-cased token compare only.

		if ( 'apache2handler' === $sapi ) {
			return 'apache';
		}
		if ( in_array( $sapi, array( 'fpm-fcgi', 'cgi-fcgi', 'litespeed' ), true ) ) {
			return 'fpm';
		}
		if ( false !== strpos( $software, 'nginx' ) ) {
			return 'nginx';
		}
		if ( false !== strpos( $software, 'apache' ) ) {
			return 'apache';
		}
		return 'unknown';
	}

	/**
	 * The nginx server-block snippet the admin pastes by hand, with the live
	 * resolved guard path.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	public function nginx_snippet() {
		$path = $this->prepend_path();
		return "location ~ \\.php\$ {\n"
			. "    # ReportedIP Hive WAF — run the guard before PHP handles the request\n"
			. '    fastcgi_param PHP_VALUE "auto_prepend_file=' . $path . "\";\n"
			. "    # keep your existing fastcgi_pass / include fastcgi_params directives below\n"
			. '}';
	}

	/**
	 * The php.ini / hosting-panel directive line, the manual alternative to the
	 * nginx snippet on stacks where the operator can edit PHP settings (ISPConfig,
	 * Plesk, cPanel "PHP options"). A php-fpm reload applies it.
	 *
	 * @return string
	 * @since  2.1.3
	 */
	public function php_ini_snippet() {
		return 'auto_prepend_file = ' . $this->prepend_path();
	}

	/**
	 * Absolute path of the generated guard file.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	public function prepend_path() {
		if ( ! defined( 'WP_CONTENT_DIR' ) ) {
			return '';
		}
		return rtrim( WP_CONTENT_DIR, '/\\' ) . '/' . self::PREPEND_FILENAME;
	}

	/**
	 * True when PHP can write the directive target for the detected server.
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	public function is_writable_target() {
		$server = $this->detect_server();
		if ( 'nginx' === $server || 'unknown' === $server ) {
			$dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : '';
			return '' !== $dir && is_writable( $dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host writability probe; WP_Filesystem cannot place an auto_prepend target.
		}
		$file = ( 'fpm' === $server ) ? $this->user_ini_path() : $this->htaccess_path();
		if ( '' === $file ) {
			return false;
		}
		return file_exists( $file )
			? is_writable( $file ) // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host writability probe.
			: is_writable( dirname( $file ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host directory writability probe.
	}

	/**
	 * Resolve the `.htaccess` path via the WP-Admin helper.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	private function htaccess_path() {
		$home = $this->home_path();
		return '' === $home ? '' : $home . '.htaccess';
	}

	/**
	 * Resolve the `.user.ini` path in the document root.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	private function user_ini_path() {
		$home = $this->home_path();
		return '' === $home ? '' : $home . '.user.ini';
	}

	/**
	 * Site home path with a trailing slash, or empty when unavailable.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	private function home_path() {
		if ( ! function_exists( 'get_home_path' ) && defined( 'ABSPATH' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( ! function_exists( 'get_home_path' ) ) {
			return '';
		}
		$home = get_home_path();
		if ( ! is_string( $home ) || '' === $home ) {
			return '';
		}
		return rtrim( $home, '/\\' ) . '/';
	}

	/**
	 * The `.htaccess` directive lines (mod_php only — gated by detect_server).
	 *
	 * @param string $prepend Guard path.
	 * @return string[]
	 * @since  2.1.2
	 */
	private function htaccess_lines( $prepend ) {
		return array( 'php_value auto_prepend_file "' . $prepend . '"' );
	}

	/**
	 * The `.user.ini` directive lines (PHP-FPM/CGI).
	 *
	 * @param string $prepend Guard path.
	 * @return string[]
	 * @since  2.1.2
	 */
	private function user_ini_lines( $prepend ) {
		return array( 'auto_prepend_file=' . $prepend );
	}

	/**
	 * Write an idempotent marker block into a `.user.ini` file, creating it when
	 * the directory is writable.
	 *
	 * The PHP INI parser only accepts `;` comments — `#` was removed in PHP 7,
	 * and WordPress' insert_with_markers() instruction comment even contains
	 * parentheses, which abort `.user.ini` parsing with a syntax error BEFORE
	 * the directive line is reached. The block therefore uses `;` markers and
	 * nothing but the bare directive lines in between.
	 *
	 * @param string   $file  Target `.user.ini` file.
	 * @param string[] $lines Directive lines.
	 * @return bool
	 * @since  2.1.7
	 */
	private function write_user_ini_directive( $file, array $lines ) {
		if ( '' === $file ) {
			return false;
		}
		if ( ! file_exists( $file ) ) {
			if ( ! is_writable( dirname( $file ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host directory writability probe.
				return false;
			}
			if ( false === file_put_contents( $file, '' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Creating an empty same-host config file before writing the marker block.
				return false;
			}
		}
		if ( ! is_readable( $file ) || ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host writability probe.
			return false;
		}
		$contents = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a same-host config file to replace our marker block.
		if ( false === $contents ) {
			return false;
		}
		$contents = rtrim( $this->remove_marker_block( $contents ), "\r\n" );
		$block    = '; BEGIN ' . self::MARKER . "\n" . implode( "\n", $lines ) . "\n; END " . self::MARKER . "\n";
		$contents = ( '' === $contents ) ? $block : $contents . "\n" . $block;
		return false !== file_put_contents( $file, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writing back the same-host config file with the refreshed marker block.
	}

	/**
	 * Write an idempotent marker block into a config file, creating it when the
	 * directory is writable.
	 *
	 * @param string   $file  Target config file.
	 * @param string[] $lines Directive lines.
	 * @return bool
	 * @since  2.1.2
	 */
	private function write_directive( $file, array $lines ) {
		if ( '' === $file ) {
			return false;
		}
		if ( ! function_exists( 'insert_with_markers' ) && defined( 'ABSPATH' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			return false;
		}
		if ( ! file_exists( $file ) ) {
			if ( ! is_writable( dirname( $file ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host directory writability probe.
				return false;
			}
			if ( false === file_put_contents( $file, '' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Creating an empty same-host config file before insert_with_markers().
				return false;
			}
		}
		if ( ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host writability probe.
			return false;
		}
		return (bool) insert_with_markers( $file, self::MARKER, $lines );
	}

	/**
	 * Strip the marker block from a config file if present. A missing file is a
	 * success (nothing to strip).
	 *
	 * @param string $file Target config file.
	 * @return bool
	 * @since  2.1.2
	 */
	private function strip_directive( $file ) {
		if ( '' === $file || ! file_exists( $file ) ) {
			return true;
		}
		if ( ! is_readable( $file ) || ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host writability probe.
			return false;
		}
		$contents = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a same-host config file to strip our marker.
		if ( false === $contents ) {
			return false;
		}
		$stripped = $this->remove_marker_block( $contents );
		if ( $stripped === $contents ) {
			return true;
		}
		return false !== file_put_contents( $file, ltrim( $stripped, "\r\n" ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writing back the stripped same-host config file.
	}

	/**
	 * Remove every marker block variant from a config file body: the `#` block
	 * insert_with_markers() writes into `.htaccess` and the `;` block the
	 * `.user.ini` writer uses (plus the broken legacy `#` block that pre-2.1.7
	 * versions wrote into `.user.ini`).
	 *
	 * @param string $contents Config file body.
	 * @return string Body without marker blocks.
	 * @since  2.1.7
	 */
	private function remove_marker_block( $contents ) {
		$marker   = preg_quote( self::MARKER, '/' );
		$pattern  = '/[#;] BEGIN ' . $marker . '.*?[#;] END ' . $marker . '\R?/s';
		$stripped = preg_replace( $pattern, '', $contents );
		return null === $stripped ? $contents : $stripped;
	}

	/**
	 * Build the self-contained guard PHP with the active rules and the IP
	 * whitelist baked in. The guard is fail-open and runs without WordPress.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	private function generate_prepend() {
		$rules      = class_exists( 'ReportedIP_Hive_WAF' ) ? ReportedIP_Hive_WAF::get_instance()->get_active_rules() : array();
		$whitelist  = $this->whitelist_snapshot();
		$exceptions = $this->exceptions_snapshot();

		$rules_export  = var_export( array_values( $rules ), true );      // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Baking a literal rules array into a generated PHP file, not debugging.
		$wl_export     = var_export( array_values( $whitelist ), true );  // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Baking a literal whitelist array into a generated PHP file, not debugging.
		$ex_export     = var_export( array_values( $exceptions ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Baking the literal WAF-exception allowlist into a generated PHP file, not debugging.
		$header_export = var_export( (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Baking the trusted proxy header literal into a generated PHP file, not debugging.
		$version       = self::DROPIN_VERSION;

		$engine_enabled = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_ENABLED, true );
		$report_only    = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_REPORT_ONLY, false );
		$skip_authed    = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED, true );

		$engine_export = $engine_enabled ? 'true' : 'false';
		$report_export = $report_only ? 'true' : 'false';
		$skip_export   = $skip_authed ? 'true' : 'false';

		$template = <<<'PHP'
<?php
/**
 * ReportedIP Hive WAF drop-in — AUTO-GENERATED, DO NOT EDIT.
 * Regenerated by ReportedIP_Hive_WAF_Dropin_Manager on rule sync / self-heal.
 * Format version: __RIP_VERSION__. Fail-open: any error lets the request through.
 */
if ( defined( 'REPORTEDIP_HIVE_WAF_DROPIN' ) ) { return; }
define( 'REPORTEDIP_HIVE_WAF_DROPIN', __RIP_VERSION__ );

if ( ! function_exists( 'reportedip_hive_dropin_flatten' ) ) {
	function reportedip_hive_dropin_flatten( $value ) {
		if ( is_array( $value ) ) {
			$out = '';
			foreach ( $value as $k => $v ) { $out .= ' ' . $k . '=' . reportedip_hive_dropin_flatten( $v ); }
			return $out;
		}
		return is_scalar( $value ) ? (string) $value : '';
	}
}
if ( ! function_exists( 'reportedip_hive_dropin_ip_match' ) ) {
	function reportedip_hive_dropin_ip_match( $ip, $entry ) {
		if ( '' === $ip || '' === $entry ) { return false; }
		if ( $ip === $entry ) { return true; }
		if ( false === strpos( $entry, '/' ) ) { return false; }
		list( $subnet, $bits ) = explode( '/', $entry, 2 );
		$bits = (int) $bits;
		$ip_bin = @inet_pton( $ip );
		$net_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $net_bin || strlen( $ip_bin ) !== strlen( $net_bin ) ) { return false; }
		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;
		if ( $bytes > 0 && 0 !== substr_compare( $ip_bin, $net_bin, 0, $bytes ) ) { return false; }
		if ( 0 === $rem ) { return true; }
		$mask = chr( 0xff << ( 8 - $rem ) & 0xff );
		return ( $ip_bin[ $bytes ] & $mask ) === ( $net_bin[ $bytes ] & $mask );
	}
}
if ( ! function_exists( 'reportedip_hive_dropin_loc_match' ) ) {
	function reportedip_hive_dropin_loc_match( $ex, $path, $ip ) {
		$prefix = isset( $ex['path_prefix'] ) ? (string) $ex['path_prefix'] : '';
		if ( '' !== $prefix && ( '' === $path || 0 !== strpos( $path, $prefix ) ) ) { return false; }
		$scope_ip = isset( $ex['ip_address'] ) ? (string) $ex['ip_address'] : '';
		if ( '' !== $scope_ip && ! reportedip_hive_dropin_ip_match( $ip, $scope_ip ) ) { return false; }
		return true;
	}
}
if ( ! function_exists( 'reportedip_hive_dropin_excepted' ) ) {
	function reportedip_hive_dropin_excepted( $exceptions, $rule, $path, $ip ) {
		$rid = isset( $rule['id'] ) ? (string) $rule['id'] : '';
		$grp = isset( $rule['group'] ) ? (string) $rule['group'] : '';
		foreach ( $exceptions as $ex ) {
			$scope  = isset( $ex['scope'] ) ? (string) $ex['scope'] : '';
			$target = isset( $ex['rule_id'] ) ? (string) $ex['rule_id'] : '';
			if ( 'rule' === $scope && '' !== $target && $target === $rid && reportedip_hive_dropin_loc_match( $ex, $path, $ip ) ) { return true; }
			if ( 'group' === $scope && '' !== $target && $target === $grp && reportedip_hive_dropin_loc_match( $ex, $path, $ip ) ) { return true; }
		}
		return false;
	}
}
if ( ! function_exists( 'reportedip_hive_dropin_has_login_cookie' ) ) {
	function reportedip_hive_dropin_has_login_cookie( $cookies ) {
		if ( ! is_array( $cookies ) ) { return false; }
		foreach ( $cookies as $k => $v ) {
			if ( 0 === strncmp( (string) $k, 'wordpress_logged_in_', 20 ) && '' !== (string) $v ) { return true; }
		}
		return false;
	}
}

(function () {
	try {
		$rules      = __RIP_RULES__;
		$whitelist  = __RIP_WHITELIST__;
		$exceptions = __RIP_EXCEPTIONS__;
		if ( empty( $rules ) ) { return; }
		if ( ! __RIP_ENGINE_ENABLED__ || __RIP_REPORT_ONLY__ ) { return; }

		$ip      = '';
		$trusted = __RIP_TRUSTED_HEADER__;
		if ( '' !== $trusted && isset( $_SERVER[ $trusted ] ) ) {
			$parts     = explode( ',', (string) $_SERVER[ $trusted ] );
			$candidate = trim( $parts[0] );
			if ( false !== filter_var( $candidate, FILTER_VALIDATE_IP ) ) { $ip = $candidate; }
		}
		if ( '' === $ip ) {
			$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		}
		foreach ( $whitelist as $entry ) {
			if ( reportedip_hive_dropin_ip_match( $ip, (string) $entry ) ) { return; }
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$dec = rawurldecode( $uri );
		$req_path = (string) parse_url( $uri, PHP_URL_PATH );
		foreach ( $exceptions as $ex ) {
			if ( 'all' === ( isset( $ex['scope'] ) ? $ex['scope'] : '' ) && reportedip_hive_dropin_loc_match( $ex, $req_path, $ip ) ) { return; }
		}
		$uri_subject = ( $uri === $dec ) ? $uri : $uri . "\n" . $dec;
		$ua  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$body = '';
		$skip_body = __RIP_SKIP_AUTHED__ && reportedip_hive_dropin_has_login_cookie( $_COOKIE );
		if ( ! $skip_body ) {
			if ( ! empty( $_POST ) ) { $body .= reportedip_hive_dropin_flatten( $_POST ); }
			$raw = file_get_contents( 'php://input', false, null, 0, 65536 );
			if ( is_string( $raw ) && '' !== $raw ) { $body .= "\n" . $raw; }
		}
		$all = $uri_subject . "\n" . $body . "\n" . $ua;

		$prev = ini_get( 'pcre.backtrack_limit' );
		if ( false !== $prev ) { @ini_set( 'pcre.backtrack_limit', '100000' ); }
		$hit = null;
		foreach ( $rules as $rule ) {
			if ( empty( $rule['pattern'] ) ) { continue; }
			$target = isset( $rule['target'] ) ? $rule['target'] : 'all';
			if ( 'uri' === $target ) { $subject = $uri_subject; }
			elseif ( 'body' === $target ) { $subject = $body; }
			elseif ( 'ua' === $target ) { $subject = $ua; }
			else { $subject = $all; }
			if ( '' === $subject ) { continue; }
			$compiled = '~' . str_replace( '~', '\~', (string) $rule['pattern'] ) . '~';
			if ( 1 === @preg_match( $compiled, $subject ) ) {
				if ( reportedip_hive_dropin_excepted( $exceptions, $rule, $req_path, $ip ) ) { continue; }
				$hit = $rule; break;
			}
		}
		if ( false !== $prev ) { @ini_set( 'pcre.backtrack_limit', (string) $prev ); }

		if ( null !== $hit ) {
			$group = isset( $hit['group'] ) ? preg_replace( '/[^a-z_]/', '', (string) $hit['group'] ) : 'rule';
			if ( ! headers_sent() ) {
				header( 'HTTP/1.1 403 Forbidden' );
				header( 'X-RIP-WAF: ' . $group );
				header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			}
			echo 'Forbidden';
			exit;
		}
	} catch ( \Throwable $e ) {
		return;
	}
})();


PHP;

		return str_replace(
			array( '__RIP_VERSION__', '__RIP_RULES__', '__RIP_WHITELIST__', '__RIP_EXCEPTIONS__', '__RIP_TRUSTED_HEADER__', '__RIP_ENGINE_ENABLED__', '__RIP_REPORT_ONLY__', '__RIP_SKIP_AUTHED__' ),
			array( (string) $version, $rules_export, $wl_export, $ex_export, $header_export, $engine_export, $report_export, $skip_export ),
			$template
		);
	}

	/**
	 * Snapshot of whitelist IP/CIDR entries to bake into the guard, so a
	 * whitelisted client is never blocked by the pre-WordPress layer.
	 *
	 * @return string[]
	 * @since  2.1.2
	 */
	private function whitelist_snapshot() {
		if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
			return array();
		}
		$db = ReportedIP_Hive_Database::get_instance();
		if ( ! ( $db instanceof ReportedIP_Hive_Database ) ) {
			return array();
		}
		$out = array();
		try {
			$rows = $db->get_whitelist( true );
			if ( is_array( $rows ) ) {
				foreach ( $rows as $row ) {
					$ip = is_array( $row ) ? ( $row['ip_address'] ?? '' ) : ( is_object( $row ) ? ( $row->ip_address ?? '' ) : '' );
					if ( '' !== $ip ) {
						$out[] = (string) $ip;
					}
				}
			}
		} catch ( \Throwable $e ) {
			return array();
		}
		return $out;
	}

	/**
	 * Snapshot of the active WAF exceptions to bake into the guard, so the
	 * pre-WordPress layer honours the same allowlist as the in-WordPress engine
	 * (scope rule/group/all, with optional path-prefix and IP/CIDR scope).
	 *
	 * @return array<int,array<string,string>>
	 * @since  2.1.10
	 */
	private function exceptions_snapshot() {
		if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
			return array();
		}
		$db = ReportedIP_Hive_Database::get_instance();
		if ( ! ( $db instanceof ReportedIP_Hive_Database ) ) {
			return array();
		}
		$out = array();
		try {
			$rows = $db->get_active_waf_exceptions();
			if ( is_array( $rows ) ) {
				foreach ( $rows as $row ) {
					$r     = (array) $row;
					$out[] = array(
						'scope'       => (string) ( $r['scope'] ?? '' ),
						'rule_id'     => (string) ( $r['rule_id'] ?? '' ),
						'path_prefix' => (string) ( $r['path_prefix'] ?? '' ),
						'ip_address'  => (string) ( $r['ip_address'] ?? '' ),
					);
				}
			}
		} catch ( \Throwable $e ) {
			return array();
		}
		return $out;
	}

	/**
	 * Whether the current context is the network main site (server filesystem
	 * is shared network-wide, so only the main site manages it).
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	private function is_main_site() {
		return ! function_exists( 'is_multisite' ) || ! is_multisite() || is_main_site();
	}
}
