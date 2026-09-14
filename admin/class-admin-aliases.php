<?php
/**
 * Redirects the retired Settings and Firewall page slugs to their new home.
 *
 * WordPress core dies with a 403 for an unregistered `page=` value before
 * `admin_init` runs, so both legacy slugs stay registered as hidden pages
 * and the redirect fires at `admin_init` priority 5 (the same trick the
 * quickstart uses for the old wizard slug).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.56
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Alias table for the pre-2.1.56 admin URLs.
 *
 * @since 2.1.56
 */
class ReportedIP_Hive_Admin_Aliases {

	/**
	 * Legacy settings slug.
	 *
	 * @var string
	 */
	const SETTINGS_SLUG = 'reportedip-hive-settings';

	/**
	 * Legacy firewall slug.
	 *
	 * @var string
	 */
	const FIREWALL_SLUG = 'reportedip-hive-firewall';

	/**
	 * Wire hooks.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'maybe_redirect' ), 5 );
		add_action( 'admin_menu', array( __CLASS__, 'register_hidden_pages' ), 99 );
		add_action( 'network_admin_menu', array( __CLASS__, 'register_hidden_pages' ), 99 );
	}

	/**
	 * Resolve a legacy page/tab pair to the relative admin path.
	 *
	 * @param string $page Legacy page slug.
	 * @param string $tab  Legacy tab slug.
	 * @return string Relative admin path, or '' when the slug is not an alias.
	 */
	public static function resolve( $page, $tab ) {
		$protection = 'admin.php?page=reportedip-hive-protection';
		$tools      = 'admin.php?page=reportedip-hive-tools&tab=';
		if ( self::SETTINGS_SLUG === $page ) {
			$map = array(
				'general'        => 'admin.php?page=reportedip-hive-community',
				'detection'      => $protection . '#detection',
				'blocking'       => $protection . '#blocking',
				'hide_login'     => $protection . '#hide_login',
				'notifications'  => $protection . '#notifications',
				'privacy_logs'   => $protection . '#privacy_logs',
				'performance'    => $protection . '#performance',
				'two_factor'     => $protection . '#account_security',
				'hardening_mode' => $protection . '#hardening_mode',
			);
			return $map[ $tab ] ?? $protection;
		}
		if ( self::FIREWALL_SLUG === $page ) {
			$map = array(
				'overview'  => $protection . '#waf',
				'waf'       => $protection . '#waf',
				'bot'       => $protection . '#waf',
				'spam'      => $protection . '#registration',
				'scan'      => $protection . '#detection',
				'hardening' => $protection . '#headers',
				'rule_sync' => $tools . 'rules',
				'server'    => $tools . 'server',
			);
			return $map[ $tab ] ?? $protection . '#waf';
		}
		return '';
	}

	/**
	 * Keep the legacy slugs registered so core lets the request reach admin_init.
	 *
	 * @return void
	 */
	public static function register_hidden_pages() {
		$cap = is_network_admin() ? 'manage_network_options' : 'manage_options';
		foreach ( array( self::SETTINGS_SLUG, self::FIREWALL_SLUG ) as $slug ) {
			add_submenu_page( '', 'ReportedIP Hive', 'ReportedIP Hive', $cap, $slug, '__return_null' );
		}
	}

	/**
	 * Redirect a legacy URL.
	 *
	 * @return void
	 */
	public static function maybe_redirect() {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only redirect
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only redirect
		$path = self::resolve( $page, $tab );
		if ( '' === $path ) {
			return;
		}
		wp_safe_redirect( ReportedIP_Hive_Admin_Settings::get_admin_page_url( $path ) );
		exit;
	}
}
