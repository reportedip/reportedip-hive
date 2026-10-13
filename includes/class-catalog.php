<?php
/**
 * Catalog of the features the ReportedIP Hive Pro add-on provides.
 *
 * The free plugin describes them so the protection page, the quickstart
 * and the community page can say what the add-on offers. No code behind
 * any row lives in this plugin; the add-on brings it.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static add-on feature catalog.
 *
 * @since 3.0.0
 */
final class ReportedIP_Hive_Catalog {

	/**
	 * Product page every row links to; each `docs_url` adds one of its
	 * `#hive-...` section anchors.
	 */
	const PRODUCT_URL = 'https://reportedip.com/products/wordpress-plugin/';

	/**
	 * One row per add-on feature. Keys equal the feature keys the add-on
	 * registers in the feature matrix; a gate in the repository keeps both
	 * lists identical. Built on call so the strings are translated.
	 *
	 * `community_only` is set on a feature that needs the Community Network
	 * (its matrix row has `local => false`), so a Local Shield site can say so.
	 *
	 * @return array<string, array{label:string, description:string, tier:string, section:string, docs_url:string, community_only?:bool}>
	 * @since  3.0.0
	 */
	public static function features() {
		return array(
			'mail_relay_via_api'           => array(
				'label'          => __( 'Mail relay via reportedip.com', 'reportedip-hive' ),
				'description'    => __( 'Sends 2FA mails and alerts through a managed EU relay with its own sender reputation.', 'reportedip-hive' ),
				'tier'           => 'professional',
				'section'        => 'notifications',
				'docs_url'       => self::PRODUCT_URL . '#hive-operations',
				'community_only' => true,
			),
			'sms_relay_via_api'            => array(
				'label'          => __( 'SMS codes via the managed relay', 'reportedip-hive' ),
				'description'    => __( 'A second factor by text message, delivered through the EU gateway, no SMS provider account needed.', 'reportedip-hive' ),
				'tier'           => 'professional',
				'section'        => 'account_security',
				'docs_url'       => self::PRODUCT_URL . '#hive-identity',
				'community_only' => true,
			),
			'frontend_2fa'                 => array(
				'label'       => __( 'Storefront 2FA for WooCommerce', 'reportedip-hive' ),
				'description' => __( 'The second factor on My Account, checkout and the WooCommerce blocks, inside the theme instead of wp-login.php.', 'reportedip-hive' ),
				'tier'        => 'professional',
				'section'     => 'account_security',
				'docs_url'    => self::PRODUCT_URL . '#hive-identity',
			),
			'2fa_policies'                 => array(
				'label'       => __( 'Adaptive 2FA policies per role', 'reportedip-hive' ),
				'description' => __( 'Ask for the second factor again on a new device, address, network or country, every N days or sign-ins.', 'reportedip-hive' ),
				'tier'        => 'professional',
				'section'     => 'twofa_policies',
				'docs_url'    => self::PRODUCT_URL . '#hive-identity',
			),
			'hardening_mode'               => array(
				'label'       => __( 'Hardening mode during attack waves', 'reportedip-hive' ),
				'description' => __( 'Tightens the sign-in and reputation thresholds for an hour when a coordinated attack is detected.', 'reportedip-hive' ),
				'tier'        => 'professional',
				'section'     => 'hardening_mode',
				'docs_url'    => self::PRODUCT_URL . '#hive-response',
			),
			'form_proof_pow'               => array(
				'label'       => __( 'Computation check on forms', 'reportedip-hive' ),
				'description' => __( 'A small sum the browser works out in the background, so a script that copies the hidden field no longer passes.', 'reportedip-hive' ),
				'tier'        => 'professional',
				'section'     => 'forms',
				'docs_url'    => self::PRODUCT_URL . '#hive-forms',
			),
			'tor_blocking'                 => array(
				'label'          => __( 'Tor exit node blocking', 'reportedip-hive' ),
				'description'    => __( 'Refuses sign-in attempts from known Tor exit nodes using a signed list refreshed twice a day.', 'reportedip-hive' ),
				'tier'           => 'professional',
				'section'        => 'blocking',
				'docs_url'       => self::PRODUCT_URL . '#hive-response',
				'community_only' => true,
			),
			'security_headers_advanced'    => array(
				'label'       => __( 'Advanced security headers', 'reportedip-hive' ),
				'description' => __( 'HSTS with preload, a Content-Security-Policy builder, Permissions-Policy and the cross-origin trio.', 'reportedip-hive' ),
				'tier'        => 'professional',
				'section'     => 'headers',
				'docs_url'    => self::PRODUCT_URL . '#hive-lockdown',
			),
			'registration_rules_unlimited' => array(
				'label'       => __( 'Unlimited registration rules', 'reportedip-hive' ),
				'description' => __( 'Unlimited username and e-mail rules, regular expressions and registration restricted to allowlisted IP addresses.', 'reportedip-hive' ),
				'tier'        => 'professional',
				'section'     => 'registration',
				'docs_url'    => self::PRODUCT_URL . '#hive-forms',
			),
			'webauthn_advanced'            => array(
				'label'       => __( 'Advanced security keys', 'reportedip-hive' ),
				'description' => __( 'Several keys per account with a backup key, model detection and key lifecycle mails.', 'reportedip-hive' ),
				'tier'        => 'business',
				'section'     => 'account_security',
				'docs_url'    => self::PRODUCT_URL . '#hive-identity',
			),
			'form_adapters_advanced'       => array(
				'label'       => __( 'Advanced form protection', 'reportedip-hive' ),
				'description' => __( 'The execution proof on WPForms, Gravity Forms, Forminator, Formidable, Elementor Forms and Ultimate Member.', 'reportedip-hive' ),
				'tier'        => 'business',
				'section'     => 'forms',
				'docs_url'    => self::PRODUCT_URL . '#hive-forms',
			),
			'audit_log'                    => array(
				'label'       => __( 'Audit event trail', 'reportedip-hive' ),
				'description' => __( 'Who changed what: settings with old and new value, plugins, themes, pages, menus, files and accounts.', 'reportedip-hive' ),
				'tier'        => 'business',
				'section'     => 'privacy_logs',
				'docs_url'    => self::PRODUCT_URL . '#hive-privacy',
			),
			'cloud_management'             => array(
				'label'          => __( 'Cloud fleet management', 'reportedip-hive' ),
				'description'    => __( 'Manage this site from the reportedip.com dashboard: policies, per-site overrides and drift detection.', 'reportedip-hive' ),
				'tier'           => 'business',
				'section'        => 'performance',
				'docs_url'       => self::PRODUCT_URL . '#hive-operations',
				'community_only' => true,
			),
			'user_management'              => array(
				'label'       => __( 'User account control', 'reportedip-hive' ),
				'description' => __( 'Block accounts with a message, end their sessions and password resets, review active sessions.', 'reportedip-hive' ),
				'tier'        => 'business',
				'section'     => 'account_security',
				'docs_url'    => self::PRODUCT_URL . '#hive-identity',
			),
		);
	}

	/**
	 * Rows grouped by registry section, in catalog order.
	 *
	 * @return array<string, array<string, array<string, string|bool>>>
	 * @since  3.0.0
	 */
	public static function by_section() {
		$out = array();
		foreach ( self::features() as $key => $row ) {
			$out[ $row['section'] ][ $key ] = $row;
		}
		return $out;
	}
}
