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
 * Two side files carry the state that changes too often to bake into the guard,
 * both inside `uploads/reportedip-hive/` behind a deny rule and a per-site token:
 *
 * - `blocked-<token>.list` — every active exact-IP block as `ip<TAB>unix-expiry`
 *   (`0` = permanent). Appended in O(1) the moment a block is written, so the
 *   pre-WordPress layer refuses a known offender within the same request instead
 *   of at the next self-heal. CIDR blocks cannot be looked up this way and are
 *   baked into the guard instead.
 * - `waf-hits-<token>.ndjson` — one line per blocked request. The guard has no
 *   database and no logger, so without this queue a hit left no trace at all:
 *   no log row, no counter, no escalation, no community report. WordPress
 *   imports it on the next admin request or queue cron via {@see drain_queue()}.
 *
 * Both layers must stay behaviourally identical — see "The two WAF layers" in
 * the workspace CLAUDE.md before changing anything here.
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
	const DROPIN_VERSION = 8;

	/**
	 * Blocklist header magic. Format v1:
	 * `#rip1 D=<0|1> L=<10-digit base length> <16384 hex chars>\n`
	 * — a fixed-width 16408-byte header carrying an 8 KB membership bitmap
	 * (crc32(ip) mod 65536) plus a dirty flag and the file length as of the
	 * last full rewrite. Guards from older releases treat the header as an
	 * unmatched line and still scan the body correctly.
	 */
	/**
	 * Stores the server verdict seen during real web requests, so a headless
	 * WP-CLI sync can wire the same directive instead of falling through to
	 * "unknown" and writing nothing. See {@see detect_server()}.
	 */
	const REMEMBER_SERVER_OPTION = 'reportedip_hive_dropin_server';

	const BLOCKLIST_MAGIC = '#rip1 ';

	/**
	 * Bits in the blocklist membership bitmap (8 KB payload, 16384 hex chars).
	 */
	const BLOCKLIST_BITMAP_BITS = 65536;

	/**
	 * Byte length of the fixed-width v1 blocklist header including newline.
	 */
	const BLOCKLIST_HEADER_LEN = 16408;

	/**
	 * Byte offset of the dirty-flag digit inside the header ("#rip1 D=x").
	 */
	const BLOCKLIST_DIRTY_OFFSET = 8;

	/**
	 * Directory inside uploads that holds the hit queue.
	 */
	const QUEUE_DIRNAME = 'reportedip-hive';

	/**
	 * Hard ceiling for the queue file. The guard stops appending beyond it, so a
	 * sustained attack can never fill the disk while WordPress is unreachable.
	 */
	const QUEUE_MAX_BYTES = 2097152;

	/**
	 * Hits imported per drain pass; the remainder waits for the next one.
	 */
	const QUEUE_BATCH = 200;

	/**
	 * Drain throttle transient (back-office fast path).
	 */
	const DRAIN_THROTTLE_TRANSIENT = 'reportedip_hive_waf_queue_drain';

	/**
	 * Mutual-exclusion lock around a drain, so the queue cron and an admin
	 * request cannot import the same rotated file twice.
	 */
	const DRAIN_LOCK_TRANSIENT = 'reportedip_hive_waf_drain_lock';

	/**
	 * Most exact IP blocks mirrored into the guard's blocklist file.
	 */
	const BLOCKLIST_MAX_ENTRIES = 5000;

	/**
	 * Size at which an append-grown blocklist is rewritten from the database
	 * instead of appended to again.
	 */
	const BLOCKLIST_MAX_BYTES = 1048576;

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
		add_action( 'reportedip_hive_tier_changed', array( $this, 'queue_resync' ) );
		add_action( 'reportedip_hive_ip_blocked', array( $this, 'on_ip_blocked' ), 10, 3 );
		add_action( 'reportedip_hive_ip_unblocked', array( $this, 'on_ip_unblocked' ) );
		foreach ( array(
			ReportedIP_Hive_WAF::OPT_ENABLED,
			ReportedIP_Hive_WAF::OPT_REPORT_ONLY,
			ReportedIP_Hive_WAF::OPT_PARANOIA,
			ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED,
			'reportedip_hive_report_only_mode',
			'reportedip_hive_trusted_ip_header',
		) as $opt ) {
			add_action( 'update_option_' . $opt, array( $this, 'queue_resync' ) );
			add_action( 'update_site_option_' . $opt, array( $this, 'queue_resync' ) );
		}
		add_action( 'admin_init', array( $this, 'maybe_self_heal' ) );
		add_action( 'admin_init', array( $this, 'maybe_drain_queue' ) );
		add_action( 'reportedip_hive_process_queue', array( $this, 'run_scheduled_drain' ) );
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

		$this->ensure_queue_dir();
		$this->write_blocklist();

		$writable = file_exists( $prepend ) ? is_writable( $prepend ) : is_writable( dirname( $prepend ) );
		if ( ! $writable ) {
			return false;
		}

		$content = $this->generate_prepend();
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Generating a same-host PHP guard outside the plugin dir; WP_Filesystem cannot place an auto_prepend_file target reliably. Silenced because a permission race after the writability probe must degrade to the fail-open false return, never emit a warning into the response (headers already sent on admin screens).
		if ( false === @file_put_contents( $prepend, $content ) ) {
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

		$this->drain_queue();

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
		return false !== @file_put_contents( $prepend, $stub ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Neutralising a same-host auto_prepend_file target; WP_Filesystem cannot reliably write outside the plugin dir. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
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

		$detected = 'unknown';
		if ( 'apache2handler' === $sapi ) {
			$detected = 'apache';
		} elseif ( in_array( $sapi, array( 'fpm-fcgi', 'cgi-fcgi', 'litespeed' ), true ) ) {
			$detected = 'fpm';
		} elseif ( false !== strpos( $software, 'nginx' ) ) {
			$detected = 'nginx';
		} elseif ( false !== strpos( $software, 'apache' ) ) {
			$detected = 'apache';
		}

		/*
		 * WP-CLI has no SAPI and no SERVER_SOFTWARE, so a headless run always
		 * fell through to 'unknown' — and sync() then wrote the guard file but
		 * never the directive that loads it. A site provisioned entirely over
		 * WP-CLI (MainWP, deployment scripts) therefore reported the drop-in as
		 * enabled while it was inert until someone opened wp-admin. The verdict
		 * from real web requests is remembered so a headless sync can wire the
		 * same directive the web context would have.
		 */
		if ( 'unknown' !== $detected ) {
			if ( $detected !== (string) ReportedIP_Hive_Option_Routing::get( self::REMEMBER_SERVER_OPTION, '' ) ) {
				ReportedIP_Hive_Option_Routing::set( self::REMEMBER_SERVER_OPTION, $detected );
			}
			return $detected;
		}

		$remembered = (string) ReportedIP_Hive_Option_Routing::get( self::REMEMBER_SERVER_OPTION, '' );
		if ( in_array( $remembered, array( 'apache', 'fpm', 'nginx' ), true ) ) {
			return $remembered;
		}

		return 'unknown';
	}

	/**
	 * The web server that actually answers the request, as PHP sees it
	 * (apache|litespeed|nginx|unknown).
	 *
	 * This is a different question from {@see detect_server()}, which names the
	 * mechanism used to wire `auto_prepend_file` and therefore keys off the PHP
	 * SAPI. The SAPI cannot answer "is `.htaccess` read here": both nginx and
	 * Apache commonly run PHP through FPM, so `fpm-fcgi` covers a stack that
	 * honours `.htaccess` and one that ignores it entirely. Only the server
	 * identity settles it, hence `SERVER_SOFTWARE` before the SAPI, with
	 * `apache2handler` as the one SAPI that is proof on its own.
	 *
	 * @param string|null $sapi     Override SAPI (defaults to php_sapi_name()); for tests.
	 * @param string|null $software Override SERVER_SOFTWARE; for tests.
	 * @return string
	 * @since  2.1.31
	 */
	public function detect_web_server( $sapi = null, $software = null ) {
		$sapi = null === $sapi ? php_sapi_name() : (string) $sapi;
		if ( 'apache2handler' === $sapi ) {
			return 'apache';
		}

		if ( null === $software ) {
			$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Lower-cased token compare only.
		}
		$software = strtolower( (string) $software );

		if ( false !== strpos( $software, 'litespeed' ) ) {
			return 'litespeed';
		}
		if ( false !== strpos( $software, 'nginx' ) ) {
			return 'nginx';
		}
		if ( false !== strpos( $software, 'apache' ) ) {
			return 'apache';
		}
		if ( 'litespeed' === $sapi ) {
			return 'litespeed';
		}
		return 'unknown';
	}

	/**
	 * Whether `.htaccess` directives are honoured on this stack.
	 *
	 * Apache and LiteSpeed read them, nginx never does, and an unidentified
	 * server is treated as "no" so the UI cannot advertise a rewrite block that
	 * may be inert. Any surface that reports an `.htaccess`-based protection as
	 * active must gate on this, never on the SAPI.
	 *
	 * @param string|null $sapi     Override SAPI (defaults to php_sapi_name()); for tests.
	 * @param string|null $software Override SERVER_SOFTWARE; for tests.
	 * @return bool
	 * @since  2.1.31
	 */
	public function supports_htaccess( $sapi = null, $software = null ) {
		return in_array( $this->detect_web_server( $sapi, $software ), array( 'apache', 'litespeed' ), true );
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
			if ( false === @file_put_contents( $file, '' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Creating an empty same-host config file before writing the marker block. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
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
		return false !== @file_put_contents( $file, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Writing back the same-host config file with the refreshed marker block. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
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
			if ( false === @file_put_contents( $file, '' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Creating an empty same-host config file before insert_with_markers(). Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
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
		return false !== @file_put_contents( $file, ltrim( $stripped, "\r\n" ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Writing back the stripped same-host config file. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
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
		$report_only    = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_REPORT_ONLY, false )
			|| (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false );
		$skip_authed    = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED, true );

		$engine_export = $engine_enabled ? 'true' : 'false';
		$report_export = $report_only ? 'true' : 'false';
		$skip_export   = $skip_authed ? 'true' : 'false';

		/*
		 * Bake whether any active rule inspects the body at all, mirroring the
		 * engine's required_targets() gate — a guard whose rules only target
		 * uri/ua must never pay the 64 KB php://input read.
		 */
		$body_needed = false;
		foreach ( $rules as $rule ) {
			$target = isset( $rule['target'] ) ? (string) $rule['target'] : 'all';
			if ( 'body' === $target || 'all' === $target ) {
				$body_needed = true;
				break;
			}
		}
		$body_needed_export = $body_needed ? 'true' : 'false';

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
if ( ! function_exists( 'reportedip_hive_dropin_bl_match' ) ) {
	/* Anchored per-line match over a raw chunk of "ip\tepoch" lines; true on
	   the first unexpired (or permanent) entry for this IP. */
	function reportedip_hive_dropin_bl_match( $raw, $ip ) {
		if ( ! is_string( $raw ) || '' === $raw ) { return false; }
		$found = array();
		if ( ! @preg_match_all( '/^' . preg_quote( $ip, '/' ) . "\t(\d+)$/m", $raw, $found ) || empty( $found[1] ) ) { return false; }
		$now = time();
		foreach ( $found[1] as $stamp ) {
			$stamp = (int) $stamp;
			if ( 0 === $stamp || $stamp > $now ) { return true; }
		}
		return false;
	}
}
if ( ! function_exists( 'reportedip_hive_dropin_is_blocked' ) ) {
	/*
	 * Blocklist lookup, O(header) for the common not-blocked case.
	 *
	 * File format v1: fixed-width header "#rip1 D=<0|1> L=<10-digit base
	 * length> <16384 hex chars>\n" (16408 bytes) carrying an 8 KB / 65536-bit
	 * membership bitmap over crc32(ip), followed by "ip\tepoch" lines. A clean
	 * request reads only the header. A bitmap hit (or an unreadable bitmap —
	 * scan-more, never skip) block-reads the base region; D=1 means the append
	 * path added lines after the base length, so that tail region is also
	 * matched (a re-block extends an entry whose base line may have expired).
	 * Headerless files (from older plugin versions) take the legacy full scan.
	 * Fail-open on any error.
	 */
	function reportedip_hive_dropin_is_blocked( $file, $ip ) {
		if ( '' === $file || '' === $ip ) { return false; }
		$fh = @fopen( $file, 'rb' );
		if ( ! $fh ) { return false; }
		$verdict = false;
		$head    = @fread( $fh, 16408 );
		if ( is_string( $head ) && 0 === strncmp( $head, '#rip1 ', 6 ) && strlen( $head ) >= 16408 ) {
			$bin    = @hex2bin( substr( $head, 23, 16384 ) );
			$bucket = crc32( $ip ) % 65536;
			$maybe  = ( is_string( $bin ) && 8192 === strlen( $bin ) )
				? ( 1 === ( ( ord( $bin[ $bucket >> 3 ] ) >> ( $bucket & 7 ) ) & 1 ) )
				: true;
			$dirty   = '1' === substr( $head, 8, 1 );
			$baselen = (int) substr( $head, 12, 10 );
			if ( $maybe ) {
				$base_bytes = $baselen > 16408 ? $baselen - 16408 : PHP_INT_MAX;
				$verdict    = reportedip_hive_dropin_bl_match( @fread( $fh, $base_bytes ), $ip );
			}
			if ( ! $verdict && $dirty && $baselen > 0 && 0 === @fseek( $fh, $baselen ) ) {
				$verdict = reportedip_hive_dropin_bl_match( @stream_get_contents( $fh ), $ip );
			}
		} elseif ( is_string( $head ) && '' !== $head ) {
			$verdict = reportedip_hive_dropin_bl_match( $head . @stream_get_contents( $fh ), $ip );
		}
		@fclose( $fh );
		return $verdict;
	}
}
if ( ! function_exists( 'reportedip_hive_dropin_refuse' ) ) {
	/* Status line mirrors the CLIENT protocol and the connection is closed
	   explicitly: a hardcoded "HTTP/1.1" answer to an HTTP/1.0 client leaves
	   the connection in keep-alive limbo until the server-side timeout
	   (measured: 5 s per blocked request under ApacheBench). */
	function reportedip_hive_dropin_refuse( $header, $value ) {
		if ( ! headers_sent() ) {
			$proto = isset( $_SERVER['SERVER_PROTOCOL'] ) && is_string( $_SERVER['SERVER_PROTOCOL'] ) && 0 === strpos( $_SERVER['SERVER_PROTOCOL'], 'HTTP/' )
				? $_SERVER['SERVER_PROTOCOL']
				: 'HTTP/1.0';
			header( $proto . ' 403 Forbidden' );
			header( $header . ': ' . $value );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'Connection: close' );
		}
		echo 'Forbidden';
		exit;
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
if ( ! function_exists( 'reportedip_hive_dropin_request_has_body' ) ) {
	/* Mirrors ReportedIP_Hive_WAF::request_has_body() — keep both in sync (parity rule 1). */
	function reportedip_hive_dropin_request_has_body( $server ) {
		if ( isset( $server['CONTENT_LENGTH'] ) ) { return (int) $server['CONTENT_LENGTH'] > 0; }
		if ( isset( $server['HTTP_TRANSFER_ENCODING'] ) ) { return true; }
		$method = isset( $server['REQUEST_METHOD'] ) ? strtoupper( (string) $server['REQUEST_METHOD'] ) : 'GET';
		return ! in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true );
	}
}

(function () {
	try {
		$rules      = __RIP_RULES__;
		$whitelist  = __RIP_WHITELIST__;
		$exceptions = __RIP_EXCEPTIONS__;
		$block_cidr = __RIP_BLOCKED_CIDR__;
		$blocklist  = __RIP_BLOCKLIST__;
		if ( __RIP_REPORT_ONLY__ ) { return; }

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

		foreach ( $block_cidr as $entry ) {
			if ( reportedip_hive_dropin_ip_match( $ip, (string) $entry ) ) {
				reportedip_hive_dropin_refuse( 'X-RIP-BLOCK', 'range' );
			}
		}
		if ( reportedip_hive_dropin_is_blocked( $blocklist, $ip ) ) {
			reportedip_hive_dropin_refuse( 'X-RIP-BLOCK', 'ip' );
		}

		if ( ! __RIP_ENGINE_ENABLED__ || empty( $rules ) ) { return; }

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
		if ( ! $skip_body && __RIP_BODY_NEEDED__ && ( ! empty( $_POST ) || reportedip_hive_dropin_request_has_body( $_SERVER ) ) ) {
			if ( ! empty( $_POST ) ) { $body .= reportedip_hive_dropin_flatten( $_POST ); }
			$raw = file_get_contents( 'php://input', false, null, 0, 65536 );
			if ( is_string( $raw ) && '' !== $raw ) {
				$body .= "\n" . $raw;
				$raw_decoded = rawurldecode( $raw );
				if ( $raw_decoded !== $raw ) { $body .= "\n" . $raw_decoded; }
			}
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
			$found    = array();
			if ( 1 === @preg_match( $compiled, $subject, $found ) ) {
				if ( reportedip_hive_dropin_excepted( $exceptions, $rule, $req_path, $ip ) ) { continue; }
				$hit                   = $rule;
				$hit['matched']        = isset( $found[0] ) ? (string) $found[0] : '';
				$hit['matched_target'] = $target;
				break;
			}
		}
		if ( false !== $prev ) { @ini_set( 'pcre.backtrack_limit', (string) $prev ); }

		if ( null !== $hit ) {
			$queue = __RIP_QUEUE__;
			if ( '' !== $queue ) {
				$queued = @filesize( $queue );
				if ( false === $queued || $queued < __RIP_QUEUE_MAX__ ) {
					$row = @json_encode(
						array(
							'time'       => time(),
							'ip'         => $ip,
							'rule'       => isset( $hit['id'] ) ? (string) $hit['id'] : '',
							'group'      => isset( $hit['group'] ) ? (string) $hit['group'] : '',
							'target'     => isset( $hit['matched_target'] ) ? (string) $hit['matched_target'] : 'all',
							'severity'   => isset( $hit['severity'] ) ? (string) $hit['severity'] : 'high',
							'paranoia'   => isset( $hit['paranoia'] ) ? (int) $hit['paranoia'] : 1,
							'matched'    => substr( isset( $hit['matched'] ) ? (string) $hit['matched'] : '', 0, 160 ),
							'method'     => isset( $_SERVER['REQUEST_METHOD'] ) ? substr( (string) $_SERVER['REQUEST_METHOD'], 0, 10 ) : '',
							'uri'        => substr( $uri, 0, 256 ),
							'user_agent' => substr( $ua, 0, 200 ),
						),
						JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
					);
					if ( is_string( $row ) ) {
						@file_put_contents( $queue, $row . "\n", FILE_APPEND | LOCK_EX );
					}
				}
			}

			$group = isset( $hit['group'] ) ? preg_replace( '/[^a-z_]/', '', (string) $hit['group'] ) : 'rule';
			reportedip_hive_dropin_refuse( 'X-RIP-WAF', $group );
		}
	} catch ( \Throwable $e ) {
		return;
	}
})();


PHP;

		/*
		 * Bake the queue path even when the directory is not writable right now.
		 * Baking '' turned a transient permission problem at sync time into
		 * permanent silence: the guard kept blocking but could never report a
		 * hit, so the Firewall page showed zero WAF activity while the admin UI
		 * — which re-checks writability live — reported logging as healthy. The
		 * guard's own append is already fail-soft (@file_put_contents), so a
		 * still-unwritable path simply drops that one hit and recovers the
		 * moment permissions are fixed, without waiting for a rebake.
		 */
		$this->ensure_queue_dir();
		$queue_export = var_export( $this->queue_path(), true );     // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Baking the queue path literal into a generated PHP file, not debugging.
		$block_export = var_export( $this->blocklist_path(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Baking the blocklist path literal into a generated PHP file, not debugging.
		$cidr_export  = var_export( array_values( $this->blocked_cidr_snapshot() ), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Baking the literal CIDR blocklist into a generated PHP file, not debugging.

		return str_replace(
			array( '__RIP_VERSION__', '__RIP_RULES__', '__RIP_WHITELIST__', '__RIP_EXCEPTIONS__', '__RIP_TRUSTED_HEADER__', '__RIP_ENGINE_ENABLED__', '__RIP_REPORT_ONLY__', '__RIP_SKIP_AUTHED__', '__RIP_BODY_NEEDED__', '__RIP_QUEUE_MAX__', '__RIP_QUEUE__', '__RIP_BLOCKED_CIDR__', '__RIP_BLOCKLIST__' ),
			array( (string) $version, $rules_export, $wl_export, $ex_export, $header_export, $engine_export, $report_export, $skip_export, $body_needed_export, (string) self::QUEUE_MAX_BYTES, $queue_export, $cidr_export, $block_export ),
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
	 * Absolute path of the hit queue the guard appends to, or '' when the
	 * uploads directory is unavailable.
	 *
	 * The file lives under uploads (the one directory WordPress guarantees is
	 * writable) inside its own folder, carries a per-site token in its name and
	 * is shielded by a deny rule — it holds client IPs and must never be
	 * fetchable over HTTP.
	 *
	 * @return string
	 * @since  2.1.30
	 */
	public function queue_path() {
		$dir = $this->queue_dir();
		if ( '' === $dir ) {
			return '';
		}
		return $dir . '/waf-hits-' . substr( hash_hmac( 'sha256', 'waf-hit-queue', wp_salt( 'auth' ) ), 0, 16 ) . '.ndjson';
	}

	/**
	 * Absolute path of the blocklist the guard consults, or ''.
	 *
	 * Kept separate from the guard itself on purpose: blocks are written all the
	 * time (every escalation, every reputation verdict), while the guard carries
	 * the rule set and is expensive to rebake. A small side file can be appended
	 * to in O(1) the moment a block is written, so the pre-WordPress layer knows
	 * about an offender within the same request instead of at the next hourly
	 * self-heal.
	 *
	 * @return string
	 * @since  2.1.30
	 */
	public function blocklist_path() {
		$dir = $this->queue_dir();
		if ( '' === $dir ) {
			return '';
		}
		return $dir . '/blocked-' . substr( hash_hmac( 'sha256', 'blocklist', wp_salt( 'auth' ) ), 0, 16 ) . '.list';
	}

	/**
	 * Mirror a fresh block into the guard's blocklist.
	 *
	 * A CIDR range cannot be matched by the file's exact-IP lookup, so those
	 * (rare, always manual) entries trigger a full guard rebake instead.
	 *
	 * @param string      $ip_address    Blocked IP or CIDR.
	 * @param string      $reason        Unused, kept for the action signature.
	 * @param string|null $blocked_until UTC expiry, or null for permanent.
	 * @return void
	 * @since  2.1.30
	 */
	public function on_ip_blocked( $ip_address, $reason = '', $blocked_until = null ) {
		unset( $reason );
		if ( ! $this->is_main_site() || ! (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) ) {
			return;
		}

		$ip_address = (string) $ip_address;
		if ( '' === $ip_address ) {
			return;
		}
		if ( false !== strpos( $ip_address, '/' ) ) {
			$this->queue_resync();
			return;
		}

		$path = $this->blocklist_path();
		if ( '' === $path || ! $this->ensure_queue_dir() ) {
			return;
		}

		$size = file_exists( $path ) ? filesize( $path ) : 0;
		if ( false !== $size && $size > self::BLOCKLIST_MAX_BYTES ) {
			$this->write_blocklist();
			return;
		}

		/*
		 * Dedupe guard: skip the append when the file already carries an
		 * equal-or-stronger line for this IP (tracked per IP for an hour).
		 * A longer expiry — the escalation ladder always extends — must
		 * still append, otherwise the guard would enforce only the stale
		 * shorter block.
		 */
		$stamp         = self::expiry_stamp( $blocked_until );
		$transient_key = 'reportedip_hive_bl_appended_' . md5( $ip_address );
		$prev          = get_site_transient( $transient_key );
		if ( false !== $prev ) {
			$prev = (int) $prev;
			if ( 0 === $prev || ( 0 !== $stamp && $stamp <= $prev ) ) {
				return;
			}
		}

		$this->mark_blocklist_dirty( $path );

		@file_put_contents( $path, $ip_address . "\t" . $stamp . "\n", FILE_APPEND | LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Appending one line to a same-host lookup file the pre-WordPress guard reads; WP_Filesystem has no append mode. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
		set_site_transient( $transient_key, $stamp, HOUR_IN_SECONDS );
	}

	/**
	 * Flip the header's dirty flag so the guard knows the append region past
	 * the base length must be scanned even on a bitmap miss. No-op for
	 * headerless (legacy) files — those are always fully scanned anyway.
	 *
	 * @param string $path Blocklist path.
	 * @return void
	 * @since  2.1.32
	 */
	private function mark_blocklist_dirty( $path ) {
		if ( ! file_exists( $path ) ) {
			return;
		}
		$fh = @fopen( $path, 'r+b' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Single-byte in-place flag update on a same-host lookup file.
		if ( ! $fh ) {
			return;
		}
		$magic = fread( $fh, strlen( self::BLOCKLIST_MAGIC ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Same-host lookup file.
		if ( self::BLOCKLIST_MAGIC === $magic && 0 === fseek( $fh, self::BLOCKLIST_DIRTY_OFFSET ) ) {
			fwrite( $fh, '1' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Same-host lookup file.
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Same-host lookup file.
	}

	/**
	 * Rewrite the blocklist after a block was lifted, so the guard stops
	 * refusing an IP the admin just released.
	 *
	 * @param string $ip_address Unblocked IP (from the action); clears the
	 *                           per-IP append-dedupe marker so an immediate
	 *                           re-block is mirrored again.
	 * @return void
	 * @since  2.1.30
	 */
	public function on_ip_unblocked( $ip_address = '' ) {
		if ( ! $this->is_main_site() || ! (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) ) {
			return;
		}
		if ( '' !== (string) $ip_address ) {
			delete_site_transient( 'reportedip_hive_bl_appended_' . md5( (string) $ip_address ) );
		}
		$this->write_blocklist();
	}

	/**
	 * Rewrite the blocklist from the database, dropping expired and duplicated
	 * entries that the append path accumulates.
	 *
	 * @return bool True when the file was written.
	 * @since  2.1.30
	 */
	public function write_blocklist() {
		$path = $this->blocklist_path();
		if ( '' === $path || ! $this->ensure_queue_dir() ) {
			return false;
		}

		$lines  = array();
		$bitmap = str_repeat( "\0", self::BLOCKLIST_BITMAP_BITS / 8 );
		foreach ( $this->active_blocks() as $row ) {
			$ip = is_object( $row ) ? (string) ( $row->ip_address ?? '' ) : '';
			if ( '' === $ip || false !== strpos( $ip, '/' ) ) {
				continue;
			}
			$lines[] = $ip . "\t" . self::expiry_stamp( $row->blocked_until ?? null );

			$bucket                 = crc32( $ip ) % self::BLOCKLIST_BITMAP_BITS;
			$bitmap[ $bucket >> 3 ] = chr( ord( $bitmap[ $bucket >> 3 ] ) | ( 1 << ( $bucket & 7 ) ) );

			if ( count( $lines ) >= self::BLOCKLIST_MAX_ENTRIES ) {
				break;
			}
		}

		$body   = empty( $lines ) ? '' : implode( "\n", $lines ) . "\n";
		$header = sprintf(
			'%sD=0 L=%010d %s' . "\n",
			self::BLOCKLIST_MAGIC,
			self::BLOCKLIST_HEADER_LEN + strlen( $body ),
			bin2hex( $bitmap )
		);
		return false !== @file_put_contents( $path, $header . $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Writing the same-host lookup file the pre-WordPress guard reads. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
	}

	/**
	 * Active block rows, or an empty list when the database is unavailable.
	 *
	 * @return array<int, object>
	 * @since  2.1.30
	 */
	private function active_blocks() {
		if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
			return array();
		}
		try {
			$rows = ReportedIP_Hive_Database::get_instance()->get_blocked_ips( true );
		} catch ( \Throwable $e ) {
			return array();
		}
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Translate a UTC expiry into the guard's unix stamp (0 = permanent).
	 *
	 * The guard has no WordPress and no site timezone, so every expiry crosses
	 * the boundary as an absolute epoch value — the one representation that is
	 * identical on a German, Brazilian and Japanese install.
	 *
	 * @param string|null $blocked_until UTC 'Y-m-d H:i:s', or null.
	 * @return int
	 * @since  2.1.30
	 */
	private static function expiry_stamp( $blocked_until ) {
		if ( ! is_string( $blocked_until ) || '' === $blocked_until ) {
			return 0;
		}
		$stamp = strtotime( $blocked_until . ' UTC' );
		return ( false === $stamp || $stamp < 0 ) ? 0 : (int) $stamp;
	}

	/**
	 * Snapshot of active CIDR blocks, baked into the guard because the
	 * blocklist file only answers exact-IP lookups.
	 *
	 * @return string[]
	 * @since  2.1.30
	 */
	private function blocked_cidr_snapshot() {
		$out = array();
		foreach ( $this->active_blocks() as $row ) {
			$ip = is_object( $row ) ? (string) ( $row->ip_address ?? '' ) : '';
			if ( '' !== $ip && false !== strpos( $ip, '/' ) ) {
				$out[] = $ip;
			}
		}
		return $out;
	}

	/**
	 * Whether the guard can actually append hits.
	 *
	 * The guard runs as the web-server user and fails open on a write error, so
	 * a queue directory it cannot write to would silently swallow every hit —
	 * blocking would still work, but the log, the counters and the escalation
	 * ladder would stay empty and look exactly like "no attacks". That happens
	 * whenever the directory was created by a root WP-CLI run. The admin surface
	 * therefore reports this state instead of hiding it.
	 *
	 * @return bool
	 * @since  2.1.30
	 */
	public function queue_is_writable() {
		$dir = $this->queue_dir();
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return false;
		}
		return is_writable( $dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host writability probe for the queue the guard writes to.
	}

	/**
	 * Queue directory path, or '' when uploads are unavailable.
	 *
	 * @return string
	 * @since  2.1.30
	 */
	private function queue_dir() {
		$uploads = wp_upload_dir( null, false );
		if ( ! is_array( $uploads ) || empty( $uploads['basedir'] ) || ! empty( $uploads['error'] ) ) {
			return '';
		}
		return rtrim( (string) $uploads['basedir'], '/\\' ) . '/' . self::QUEUE_DIRNAME;
	}

	/**
	 * Create the queue directory with its access guards.
	 *
	 * @return bool True when the directory exists and is writable.
	 * @since  2.1.30
	 */
	private function ensure_queue_dir() {
		$dir = $this->queue_dir();
		if ( '' === $dir ) {
			return false;
		}
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return false;
		}

		$guards = array(
			$dir . '/index.php'  => "<?php\nreturn;\n",
			$dir . '/.htaccess'  => "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n",
			$dir . '/web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
		);
		foreach ( $guards as $file => $body ) {
			if ( ! file_exists( $file ) ) {
				@file_put_contents( $file, $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Writing same-host access guards next to the queue; WP_Filesystem is unavailable on the front end. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
			}
		}

		return is_writable( $dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Same-host writability probe.
	}

	/**
	 * Back-office fast path: drain at most once a minute so a hit shows up in
	 * the log while the admin is still looking at the page, without turning
	 * every admin request into file I/O.
	 *
	 * @return void
	 * @since  2.1.30
	 */
	public function run_scheduled_drain() {
		$this->drain_queue();
	}

	/**
	 * Back-office fast path: drain at most once a minute so a hit shows up in
	 * the log while the admin is still looking at the page, without turning
	 * every admin request into file I/O.
	 *
	 * @return void
	 * @since  2.1.30
	 */
	public function maybe_drain_queue() {
		if ( ! $this->is_main_site() ) {
			return;
		}
		if ( get_site_transient( self::DRAIN_THROTTLE_TRANSIENT ) ) {
			return;
		}
		set_site_transient( self::DRAIN_THROTTLE_TRANSIENT, 1, MINUTE_IN_SECONDS );
		$this->drain_queue();
	}

	/**
	 * Import the queued pre-WordPress hits into the log, the escalation ladder
	 * and the report queue.
	 *
	 * The live file is rotated to a `.processing` sibling first: `rename()` is
	 * atomic, so a hit arriving mid-drain lands in a fresh live file instead of
	 * being truncated away. A leftover `.processing` file from an interrupted
	 * run is picked up before a new rotation happens, so nothing is lost.
	 *
	 * @return int Number of hits imported.
	 * @since  2.1.30
	 */
	public function drain_queue() {
		if ( ! $this->is_main_site() ) {
			return 0;
		}

		$queue = $this->queue_path();
		if ( '' === $queue ) {
			return 0;
		}

		/*
		 * The rotation is atomic, the import that follows is not: the queue
		 * cron and an admin page view can reach the same `.processing` file and
		 * import every hit twice, which doubles both the log and the offence
		 * counter feeding the block ladder. The API queue worker guards itself
		 * the same way.
		 */
		if ( get_site_transient( self::DRAIN_LOCK_TRANSIENT ) ) {
			return 0;
		}
		set_site_transient( self::DRAIN_LOCK_TRANSIENT, 1, 5 * MINUTE_IN_SECONDS );

		$work = $queue . '.processing';

		try {
			if ( ! file_exists( $work ) ) {
				if ( ! file_exists( $queue ) ) {
					return 0;
				}
				if ( ! rename( $queue, $work ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic same-directory rotation; WP_Filesystem::move() is not atomic, and a non-atomic rotation loses hits arriving mid-drain.
					return 0;
				}
			}

			return $this->import_queue_file( $work );
		} finally {
			delete_site_transient( self::DRAIN_LOCK_TRANSIENT );
		}
	}

	/**
	 * Import one queue file, keeping any overflow for the next pass.
	 *
	 * @param string $file Rotated queue file.
	 * @return int Number of hits imported.
	 * @since  2.1.30
	 */
	private function import_queue_file( $file ) {
		$contents = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a same-host queue file the guard wrote.
		if ( false === $contents || '' === trim( $contents ) ) {
			wp_delete_file( $file );
			return 0;
		}

		$lines = preg_split( '/\R/', $contents, -1, PREG_SPLIT_NO_EMPTY );
		$lines = is_array( $lines ) ? $lines : array();

		$waf       = class_exists( 'ReportedIP_Hive_WAF' ) ? ReportedIP_Hive_WAF::get_instance() : null;
		$imported  = 0;
		$processed = 0;
		$overflow  = array();
		$groups    = array();

		foreach ( $lines as $line ) {
			if ( $processed >= self::QUEUE_BATCH ) {
				$overflow[] = $line;
				continue;
			}
			++$processed;
			$entry = json_decode( $line, true );
			if ( ! is_array( $entry ) || null === $waf ) {
				continue;
			}
			$this->group_entry( $groups, $entry );
		}

		foreach ( $groups as $group ) {
			if ( $waf->record_dropin_hit( $group['entry'], $group['count'], $group['targets'] ) ) {
				$imported += $group['count'];
			}
		}

		if ( empty( $overflow ) ) {
			wp_delete_file( $file );
		} else {
			@file_put_contents( $file, implode( "\n", $overflow ) . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Writing back the unprocessed tail of a same-host queue file. Silenced: an unwritable path must degrade fail-open, never print a warning into the response.
		}

		return $imported;
	}

	/**
	 * Fold one queue entry into its (IP, rule) group.
	 *
	 * A scanner sweeping twenty spellings of the same endpoint is one finding,
	 * not twenty: keeping them apart buried every other event on the firewall
	 * page and let a single ten-second burst dominate the 30-day statistic. The
	 * group keeps the earliest hit as its representative, so the imported row
	 * carries the time the sweep started.
	 *
	 * @param array<string,array<string,mixed>> $groups Groups collected so far, by reference.
	 * @param array<string,mixed>               $entry  Decoded queue entry.
	 * @return void
	 * @since  2.1.31
	 */
	private function group_entry( array &$groups, array $entry ) {
		$key = ( isset( $entry['ip'] ) ? (string) $entry['ip'] : '' ) . '|' . ( isset( $entry['rule'] ) ? (string) $entry['rule'] : '' );

		if ( ! isset( $groups[ $key ] ) ) {
			$groups[ $key ] = array(
				'entry'   => $entry,
				'count'   => 0,
				'targets' => array(),
			);
		}

		++$groups[ $key ]['count'];

		$current   = isset( $groups[ $key ]['entry']['time'] ) ? (int) $groups[ $key ]['entry']['time'] : 0;
		$candidate = isset( $entry['time'] ) ? (int) $entry['time'] : 0;
		if ( $candidate > 0 && ( 0 === $current || $candidate < $current ) ) {
			$groups[ $key ]['entry'] = $entry;
		}

		$uri = isset( $entry['uri'] ) ? (string) $entry['uri'] : '';
		if ( '' !== $uri
			&& count( $groups[ $key ]['targets'] ) < ReportedIP_Hive_WAF::AGGREGATE_URI_SAMPLE
			&& ! in_array( $uri, $groups[ $key ]['targets'], true ) ) {
			$groups[ $key ]['targets'][] = $uri;
		}
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
