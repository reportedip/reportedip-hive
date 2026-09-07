<?php
/**
 * Decoy-Path `.htaccess` writer — autonomously manages a marker block in
 * the site's root `.htaccess` so requests to known bait paths are rewritten
 * to WordPress (where the Hive Decoy-Path sensor logs the hit and emits a
 * 403). The rewrite is deliberately NOT `[F,L]` because that would short-
 * circuit PHP and skip the community-reputation report.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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
final class ReportedIP_Hive_Decoy_Htaccess_Writer extends ReportedIP_Hive_Htaccess_Block_Writer {

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
	 * Option key owning the decoy rewrite block.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	protected function option_key() {
		return 'reportedip_hive_decoy_pathblock_enabled';
	}

	/**
	 * Canonical default of the decoy master toggle.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	protected function option_default() {
		return true;
	}

	/**
	 * Apache directive lines for the decoy rewrite.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	protected function block_lines() {
		return ReportedIP_Hive_Decoy_Path_Block::htaccess_block_lines();
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
	 * After writing, ensure the Hive block sits ABOVE `# BEGIN WordPress`
	 * (otherwise the standard WP rewrite `RewriteCond %{REQUEST_FILENAME}
	 * -f → [L]` would serve a real bait file before our rewrite gets a
	 * chance).
	 *
	 * @param string $file Absolute path to `.htaccess`.
	 * @return void
	 * @since  2.1.51
	 */
	protected function after_write( $file ) {
		$this->ensure_block_position( $file );
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
