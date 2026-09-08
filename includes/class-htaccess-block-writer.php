<?php
/**
 * Shared lifecycle for every `.htaccess` marker block the plugin manages —
 * write on save, remove when the owning toggle goes off, heal once an hour
 * and report writability to the UI. Subclasses supply the marker name, the
 * option that owns the block, the directive lines and the target file.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.51
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base class for the plugin's `.htaccess` block writers.
 *
 * @since 2.1.51
 */
abstract class ReportedIP_Hive_Htaccess_Block_Writer {

	/**
	 * Marker name passed to `insert_with_markers()`. WordPress wraps it as
	 * `# BEGIN <marker>` / `# END <marker>`. Subclasses must override.
	 */
	const MARKER = '';

	/**
	 * Site-transient that throttles the admin-init self-heal to once per hour.
	 * Subclasses must override with their own key.
	 */
	const HEAL_LOCK_TRANSIENT = '';

	/**
	 * Option key whose truthiness decides whether the block is written.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	abstract protected function option_key();

	/**
	 * Canonical default of {@see self::option_key()} — must match the value
	 * in `ReportedIP_Hive_Defaults::SAFE_OPTIONS`.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	abstract protected function option_default();

	/**
	 * Directive lines placed between the markers.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	abstract protected function block_lines();

	/**
	 * Absolute path of the `.htaccess` this writer owns, or empty string when
	 * it cannot be resolved.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	abstract public function get_target_path();

	/**
	 * Hook for subclasses that need to touch the file after a successful
	 * write (the decoy writer moves its block to the top).
	 *
	 * @param string $file Absolute path to the written `.htaccess`.
	 * @return void
	 * @since  2.1.51
	 */
	protected function after_write( $file ) {
		unset( $file );
	}

	/**
	 * Wire settings-save and self-heal hooks.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function register_hooks() {
		$option = $this->option_key();
		add_action( 'update_option_' . $option, array( $this, 'on_settings_changed' ), 10, 0 );
		add_action( 'update_site_option_' . $option, array( $this, 'on_settings_changed' ), 10, 0 );
		add_action( 'admin_init', array( $this, 'maybe_self_heal' ) );
	}

	/**
	 * Action callback for the option-change hook — discards the boolean
	 * return value of `sync()` so PHPStan recognises the void contract of
	 * a WordPress action.
	 *
	 * @return void
	 * @since  2.1.51
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
	 * @since  2.1.51
	 */
	public function maybe_self_heal() {
		if ( get_site_transient( static::HEAL_LOCK_TRANSIENT ) ) {
			return;
		}
		set_site_transient( static::HEAL_LOCK_TRANSIENT, 1, HOUR_IN_SECONDS );
		$this->sync();
	}

	/**
	 * Idempotently write or remove the marker block, depending on the owning
	 * toggle. A disabled block is stripped entirely — an empty
	 * `# BEGIN`/`# END` skeleton would read as "managed" to anyone looking at
	 * the file and to our own `is_block_present()` probe.
	 *
	 * @return bool True when the file matches the desired state afterwards.
	 * @since  2.1.51
	 */
	public function sync() {
		if ( ! $this->load_wp_admin_helpers() ) {
			return false;
		}

		$file = $this->get_target_path();
		if ( '' === $file ) {
			return false;
		}

		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( $this->option_key(), $this->option_default() ) ) {
			if ( ! file_exists( $file ) ) {
				return true;
			}
			$this->remove();
			return true;
		}

		if ( ! $this->ensure_file_exists( $file ) ) {
			return false;
		}

		if ( ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Writability probe for the same-host .htaccess; WP_Filesystem is unavailable here and unnecessary.
			return false;
		}

		if ( ! insert_with_markers( $file, static::MARKER, $this->block_lines() ) ) {
			return false;
		}

		$this->after_write( $file );

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
	 * @since  2.1.51
	 */
	public function remove() {
		if ( ! $this->load_wp_admin_helpers() ) {
			return false;
		}
		$file = $this->get_target_path();
		if ( '' === $file || ! file_exists( $file ) || ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Writability probe for the same-host .htaccess; WP_Filesystem is unavailable here and unnecessary.
			return false;
		}

		$contents = file_get_contents( $file );
		if ( false === $contents ) {
			return false;
		}

		$pattern  = '/# BEGIN ' . preg_quote( static::MARKER, '/' ) . '.*?# END ' . preg_quote( static::MARKER, '/' ) . '\R?/s';
		$stripped = preg_replace( $pattern, '', $contents );
		if ( null === $stripped || $stripped === $contents ) {
			return false;
		}

		return false !== file_put_contents( $file, ltrim( $stripped, "\r\n" ) );
	}

	/**
	 * True when the target file exists and is writable by PHP, or when it
	 * does not exist yet but its directory is writable.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	public function is_writable_target() {
		$file = $this->get_target_path();
		if ( '' === $file ) {
			return false;
		}
		if ( file_exists( $file ) ) {
			return is_writable( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Writability probe for the same-host .htaccess; WP_Filesystem is unavailable here and unnecessary.
		}
		$dir = dirname( $file );
		return is_writable( $dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Writability probe for the same-host .htaccess directory; WP_Filesystem is unavailable here and unnecessary.
	}

	/**
	 * True when a `# BEGIN <marker>` line is present in the target file.
	 * Used by the settings UI status boxes and by the score.
	 *
	 * @return bool
	 * @since  2.1.51
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
		return false !== strpos( $contents, '# BEGIN ' . static::MARKER );
	}

	/**
	 * Load `wp-admin/includes/file.php` + `misc.php` on demand. They expose
	 * `get_home_path()` and `insert_with_markers()`, neither of which is
	 * autoloaded on front-end requests.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	protected function load_wp_admin_helpers() {
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
	 * @since  2.1.51
	 */
	protected function ensure_file_exists( $file ) {
		if ( file_exists( $file ) ) {
			return true;
		}
		$dir = dirname( $file );
		if ( ! is_writable( $dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Writability probe for the same-host .htaccess directory; WP_Filesystem is unavailable here and unnecessary.
			return false;
		}
		return false !== file_put_contents( $file, '' );
	}
}
