<?php
/**
 * Decoy-Path `.htaccess` writer — autonomously manages a marker block in
 * the site's root `.htaccess` so requests to known bait paths are rewritten
 * to WordPress (where the Hive Decoy-Path sensor logs the hit and emits a
 * 403). The rewrite is deliberately NOT `[F,L]` because that would short-
 * circuit PHP and skip the community-reputation report.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.11
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages the Hive decoy block inside `.htaccess`.
 *
 * @since 2.0.11
 */
final class ReportedIP_Hive_Decoy_Htaccess_Writer {

	/**
	 * Marker name passed to `insert_with_markers()`. WP wraps it as
	 * `# BEGIN ReportedIP Hive Decoy` / `# END ReportedIP Hive Decoy`.
	 */
	const MARKER = 'ReportedIP Hive Decoy';

	/**
	 * Site-transient that throttles the admin-init self-heal to once per hour.
	 */
	const HEAL_LOCK_TRANSIENT = 'reportedip_hive_decoy_htaccess_heal';

	/**
	 * @var self|null
	 */
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
	 * Wire activation/deactivation, settings-save and self-heal hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'update_option_reportedip_hive_decoy_pathblock_enabled', array( $this, 'on_settings_changed' ), 10, 0 );
		add_action( 'update_site_option_reportedip_hive_decoy_pathblock_enabled', array( $this, 'on_settings_changed' ), 10, 0 );
		add_action( 'admin_init', array( $this, 'maybe_self_heal' ) );
	}

	/**
	 * Action callback for the option-change hook — discards the boolean
	 * return value of `sync()` so PHPStan recognises the void contract of
	 * a WordPress action.
	 *
	 * @return void
	 */
	public function on_settings_changed() {
		$this->sync();
	}

	/**
	 * Throttled self-heal — re-syncs the marker block at most once per hour
	 * so manual filter extensions or third-party `.htaccess` rewrites are
	 * caught without thrashing the disk on every admin page load.
	 *
	 * @return void
	 */
	public function maybe_self_heal() {
		if ( get_site_transient( self::HEAL_LOCK_TRANSIENT ) ) {
			return;
		}
		set_site_transient( self::HEAL_LOCK_TRANSIENT, 1, HOUR_IN_SECONDS );
		$this->sync();
	}

	/**
	 * Idempotently write or remove the marker block, depending on the master
	 * toggle. After writing, ensure the Hive block sits ABOVE
	 * `# BEGIN WordPress` (otherwise the standard WP rewrite
	 * `RewriteCond %{REQUEST_FILENAME} -f → [L]` would serve a real bait
	 * file before our rewrite gets a chance).
	 *
	 * @return bool True on a successful write/remove, false on failure
	 *              (missing file, not writable, WP-Core helpers unavailable).
	 */
	public function sync() {
		if ( ! $this->load_wp_admin_helpers() ) {
			return false;
		}

		$enabled = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_decoy_pathblock_enabled', true );
		$file    = $this->get_target_path();
		if ( '' === $file ) {
			return false;
		}

		if ( ! $this->ensure_file_exists( $file ) ) {
			return false;
		}

		if ( ! is_writable( $file ) ) {
			return false;
		}

		$lines = $enabled ? ReportedIP_Hive_Decoy_Path_Block::htaccess_block_lines() : array();
		if ( ! insert_with_markers( $file, self::MARKER, $lines ) ) {
			return false;
		}

		if ( $enabled ) {
			$this->ensure_block_position( $file );
		}

		return true;
	}

	/**
	 * Remove the marker block unconditionally. Called on deactivation.
	 *
	 * `insert_with_markers( …, [] )` leaves an empty `# BEGIN … # END …`
	 * skeleton behind which is harmless but ugly. We strip the entire
	 * marker pair ourselves so deactivation truly restores the original
	 * `.htaccess`.
	 *
	 * @return bool
	 */
	public function remove() {
		if ( ! $this->load_wp_admin_helpers() ) {
			return false;
		}
		$file = $this->get_target_path();
		if ( '' === $file || ! file_exists( $file ) || ! is_writable( $file ) ) {
			return false;
		}

		$contents = file_get_contents( $file );
		if ( false === $contents ) {
			return false;
		}

		$pattern  = '/# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\R?/s';
		$stripped = preg_replace( $pattern, '', $contents );
		if ( null === $stripped || $stripped === $contents ) {
			return false;
		}

		return false !== file_put_contents( $file, ltrim( $stripped, "\r\n" ) );
	}

	/**
	 * @return string Full path to the site's `.htaccess`, or empty string.
	 */
	public function get_target_path() {
		if ( ! function_exists( 'get_home_path' ) ) {
			return '';
		}
		$home = get_home_path();
		if ( ! is_string( $home ) || '' === $home ) {
			return '';
		}
		return rtrim( $home, '/\\' ) . '/.htaccess';
	}

	/**
	 * True when the `.htaccess` file exists and is writable by PHP.
	 *
	 * @return bool
	 */
	public function is_writable_target() {
		$file = $this->get_target_path();
		if ( '' === $file ) {
			return false;
		}
		if ( file_exists( $file ) ) {
			return is_writable( $file );
		}
		$dir = dirname( $file );
		return is_writable( $dir );
	}

	/**
	 * True when a `# BEGIN ReportedIP Hive Decoy` marker is present in
	 * `.htaccess`. Used by the PHP fallback hook to annotate its log entry
	 * and by the Settings UI status box.
	 *
	 * @return bool
	 */
	public function is_block_present() {
		$this->load_wp_admin_helpers();
		$file = $this->get_target_path();
		if ( '' === $file || ! file_exists( $file ) || ! is_readable( $file ) ) {
			return false;
		}
		$contents = file_get_contents( $file );
		if ( false === $contents ) {
			return false;
		}
		return false !== strpos( $contents, '# BEGIN ' . self::MARKER );
	}

	/**
	 * Load `wp-admin/includes/file.php` + `misc.php` on demand. They expose
	 * `get_home_path()` and `insert_with_markers()`, neither of which is
	 * autoloaded on front-end requests.
	 *
	 * @return bool
	 */
	private function load_wp_admin_helpers() {
		if ( ! function_exists( 'get_home_path' ) && defined( 'ABSPATH' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( ! function_exists( 'insert_with_markers' ) && defined( 'ABSPATH' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		return function_exists( 'get_home_path' ) && function_exists( 'insert_with_markers' );
	}

	/**
	 * Create an empty `.htaccess` if the directory is writable and no file
	 * exists yet. WordPress itself does the same dance in
	 * `save_mod_rewrite_rules()`.
	 *
	 * @param string $file Absolute path to `.htaccess`.
	 * @return bool True when the file exists after the call.
	 */
	private function ensure_file_exists( $file ) {
		if ( file_exists( $file ) ) {
			return true;
		}
		$dir = dirname( $file );
		if ( ! is_writable( $dir ) ) {
			return false;
		}
		return false !== file_put_contents( $file, '' );
	}

	/**
	 * Move the Hive marker block to the very top of `.htaccess` if it is
	 * not already there. `insert_with_markers()` appends at the end of the
	 * file, but our rewrite must run before any existing Apache directive —
	 * specifically before WordPress's own `RewriteCond %{REQUEST_FILENAME}
	 * -f → [L]` short-circuit and the Multisite `RewriteRule
	 * ^([_0-9a-zA-Z-]+/)?(.*\.php)$ $2 [L]` subdir-prefix stripper, either
	 * of which would otherwise consume a bait-path request before the
	 * Hive rewrite is reached.
	 *
	 * @param string $file Absolute path to `.htaccess`.
	 * @return void
	 */
	private function ensure_block_position( $file ) {
		if ( ! is_readable( $file ) ) {
			return;
		}
		$contents = file_get_contents( $file );
		if ( false === $contents || '' === $contents ) {
			return;
		}

		$begin_hive = '# BEGIN ' . self::MARKER;
		$end_hive   = '# END ' . self::MARKER;

		$hive_pos = strpos( $contents, $begin_hive );
		if ( false === $hive_pos ) {
			return;
		}

		$prefix = substr( $contents, 0, $hive_pos );
		if ( strspn( $prefix, " \t\r\n" ) === strlen( $prefix ) ) {
			return;
		}

		$end_hive_pos = strpos( $contents, $end_hive, $hive_pos );
		if ( false === $end_hive_pos ) {
			return;
		}
		$end_hive_pos  += strlen( $end_hive );
		$content_length = strlen( $contents );
		while ( $end_hive_pos < $content_length && in_array( $contents[ $end_hive_pos ], array( "\n", "\r" ), true ) ) {
			++$end_hive_pos;
		}

		$hive_block = rtrim( substr( $contents, $hive_pos, $end_hive_pos - $hive_pos ), "\r\n" ) . "\n";
		$without    = ltrim( substr( $contents, 0, $hive_pos ) . substr( $contents, $end_hive_pos ), "\r\n" );

		$new_contents = $hive_block . "\n" . $without;
		if ( $new_contents === $contents ) {
			return;
		}
		file_put_contents( $file, $new_contents );
	}
}
