<?php
/**
 * Uploads `.htaccess` writer, refuses requests for executable file types
 * inside the uploads directory. A dropped web shell is the standard second
 * stage after an arbitrary-file-upload bug; the directory holds media, never
 * code, so denying the request outright costs nothing.
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
 * Manages the Hive uploads block inside the uploads `.htaccess`.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_Uploads_Htaccess_Writer extends ReportedIP_Hive_Htaccess_Block_Writer {

	/**
	 * Marker name passed to `insert_with_markers()`.
	 */
	const MARKER = 'ReportedIP Hive Uploads';

	/**
	 * Site-transient that throttles the admin-init self-heal to once per hour.
	 */
	const HEAL_LOCK_TRANSIENT = 'reportedip_hive_uploads_htaccess_heal';

	/**
	 * Option key owning this block. Mirrors
	 * `ReportedIP_Hive_Attack_Surface::OPT_UPLOADS_PHP`, the writer stays
	 * loadable without the runtime class (activation, uninstall).
	 */
	const OPTION = 'reportedip_hive_block_uploads_php';

	/**
	 * Extensions the block refuses. Everything a stack might hand to an
	 * interpreter, not just PHP.
	 */
	const DENIED_EXTENSIONS = 'php|phtml|php[0-9]|phps|phar|pl|py|cgi|sh|shtml';

	/**
	 * Tail of the extension match. A denied extension counts wherever it is
	 * followed by another dot or ends the name, so the classic double
	 * extension (`shell.php.jpg`, which an `AddHandler`/`AddType` stack still
	 * hands to the interpreter) is refused as well. Deliberately not an
	 * unanchored match: `\.sh` anywhere would also refuse `summer.shirt.jpg`.
	 */
	const EXTENSION_TAIL = '(\.|$)';

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
	 * Option key owning the uploads block.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	protected function option_key() {
		return self::OPTION;
	}

	/**
	 * Canonical default of the uploads-block toggle.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	protected function option_default() {
		return false;
	}

	/**
	 * Directive lines for the block.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	protected function block_lines() {
		return self::htaccess_block_lines();
	}

	/**
	 * Absolute path of the uploads `.htaccess`, or empty string when the
	 * uploads directory cannot be resolved.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public function get_target_path() {
		$basedir = self::uploads_basedir();
		return '' === $basedir ? '' : $basedir . '/.htaccess';
	}

	/**
	 * Uploads base directory of the **main** site.
	 *
	 * On a modern network every sub-site stores below
	 * `wp-content/uploads/sites/<id>/`, so one file at the main-site basedir
	 * covers the whole network through directory inheritance. Legacy
	 * `blogs.dir` networks are not covered, the UI warns about that.
	 *
	 * @return string Absolute path without a trailing slash, or empty string.
	 * @since  2.1.51
	 */
	public static function uploads_basedir() {
		$dir = self::main_site_upload_dir();

		if ( ! empty( $dir['error'] ) || empty( $dir['basedir'] ) ) {
			return '';
		}

		return rtrim( (string) $dir['basedir'], '/\\' );
	}

	/**
	 * `wp_get_upload_dir()` of the main site. Single resolver so path and URL
	 * can never disagree about which site's uploads directory is meant.
	 *
	 * @return array<string,mixed>
	 * @since  2.1.51
	 */
	private static function main_site_upload_dir() {
		$switched = false;

		if ( is_multisite() && function_exists( 'get_main_site_id' ) && get_current_blog_id() !== get_main_site_id() ) {
			switch_to_blog( get_main_site_id() );
			$switched = true;
		}

		$dir = wp_get_upload_dir();

		if ( $switched ) {
			restore_current_blog();
		}

		return is_array( $dir ) ? $dir : array();
	}

	/**
	 * URL path component of the main site's uploads directory, e.g.
	 * `/wp-content/uploads`. Used by the nginx snippet.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function uploads_url_path() {
		$dir = self::main_site_upload_dir();

		$baseurl = empty( $dir['baseurl'] ) ? '' : (string) $dir['baseurl'];
		$path    = '' === $baseurl ? '' : (string) wp_parse_url( $baseurl, PHP_URL_PATH );

		return '' === $path ? '/wp-content/uploads' : rtrim( $path, '/' );
	}

	/**
	 * Apache directive lines refusing executable file types.
	 *
	 * Deliberately no `php_flag engine off` and no `Options -ExecCGI`: both
	 * return a 500 when mod_php is absent or `AllowOverride Options` is not
	 * granted, and `Require all denied` already refuses the request before
	 * any handler sees it.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	public static function htaccess_block_lines() {
		return array(
			'<FilesMatch "(?i)\.(' . self::DENIED_EXTENSIONS . ')' . self::EXTENSION_TAIL . '">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order allow,deny',
			'        Deny from all',
			'    </IfModule>',
			'</FilesMatch>',
		);
	}

	/**
	 * Apache snippet as plain text for the UI preview and as copy-paste
	 * fallback when the file is not writable.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function htaccess_snippet() {
		$lines = array( '# ReportedIP Hive: no PHP execution in uploads (Apache)' );
		$lines = array_merge( $lines, self::htaccess_block_lines() );
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * nginx snippet for the site's `server { ... }` block.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function nginx_snippet() {
		$lines   = array();
		$lines[] = '# ReportedIP Hive: no PHP execution in uploads (nginx)';
		$lines[] = '# Place this ABOVE your "location ~ \.php$" block.';
		$lines[] = 'location ~* ^' . self::uploads_url_path() . '/.*\.(' . self::DENIED_EXTENSIONS . ')' . self::EXTENSION_TAIL . ' {';
		$lines[] = '    deny all;';
		$lines[] = '}';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Whether the block is actually in force: switched on, on a stack that
	 * reads `.htaccess`, and physically present in the file. nginx never
	 * reads as effective, the operator has to paste the snippet there.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	public function is_effective() {
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( self::OPTION, false ) ) {
			return false;
		}
		if ( ! class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' )
			|| ! ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->supports_htaccess() ) {
			return false;
		}
		return $this->is_block_present();
	}
}
