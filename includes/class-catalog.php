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
	const PRODUCT_URL = 'https://reportedip.com/products/wordpress-plugin/?rc=hive-plugin';

	/**
	 * The add-on page of the account dashboard on reportedip.com, where the
	 * add-on is downloaded. A signed-out visitor is sent through the login
	 * and lands there afterwards.
	 */
	const ACCOUNT_URL = 'https://reportedip.com/dashboard/product-hive/?rc=hive-plugin';

	/**
	 * Price list of the plans.
	 */
	const PRICING_URL = 'https://reportedip.com/pricing/?rc=hive-plugin';

	/**
	 * Campaign source of every link inside the plugin.
	 */
	const RC_PLUGIN = 'hive-plugin';

	/**
	 * Campaign source of the badges and banners on visitors' pages.
	 */
	const RC_BADGE = 'hive-badge';

	/**
	 * Paths on reportedip.com that never carry a campaign tag: the REST
	 * API, feeds, legal pages and the GDPR request page.
	 */
	const CAMPAIGN_EXEMPT = '#^/(?:wp-json/|feed/|(?:[a-z]{2}/)?feed/|datenschutzerklaerung/|impressum/|nutzungsbedingungen/|agb/|privacy|terms|dashboard/dsgvo)#i';

	/**
	 * Paths on reportedip.com that exist in one language only: the REST API,
	 * feeds, downloads, the agent installer and the legal pages. Links to them
	 * keep the unprefixed address, a language prefix would end in a 404.
	 */
	const LOCALIZE_EXEMPT = '#^/(?:wp-json/|feed/|download/|agent/|datenschutzerklaerung/|impressum/|nutzungsbedingungen/|agb/|legal/|privacy|terms|(?:de|fr|es)/)|\.[a-z0-9]{2,5}$#i';

	/**
	 * Languages reportedip.com is published in besides English.
	 */
	const SITE_LANGUAGES = array( 'de', 'fr', 'es' );

	/**
	 * Point a reportedip.com link at the page in the admin's language.
	 *
	 * reportedip.com is published in English, German, French and Spanish.
	 * The plugin links were English only, so a site run in German sent its
	 * admin to the English pricing and product pages. The language comes from
	 * the locale WordPress shows the admin in; anything outside the three
	 * site languages keeps the English page.
	 *
	 * @param string $url    Link.
	 * @param string $locale WordPress locale, '' for the current one.
	 * @return string
	 * @since  3.0.9
	 */
	public static function localize_url( $url, $locale = '' ) {
		$url  = (string) $url;
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( 'reportedip.com' !== $host && 'www.reportedip.com' !== $host ) {
			return $url;
		}
		if ( '' === $locale ) {
			$locale = function_exists( 'determine_locale' ) ? determine_locale() : get_locale();
		}
		$lang = strtolower( substr( (string) $locale, 0, 2 ) );
		if ( ! in_array( $lang, self::SITE_LANGUAGES, true ) ) {
			return $url;
		}
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		$path = '' === $path ? '/' : $path;
		if ( preg_match( self::LOCALIZE_EXEMPT, $path ) ) {
			return $url;
		}
		$origin = substr( $url, 0, (int) strpos( $url, $host ) + strlen( $host ) );
		return $origin . '/' . $lang . $path . substr( $url, strlen( $origin ) + strlen( (string) wp_parse_url( $url, PHP_URL_PATH ) ) );
	}

	/**
	 * `clean_url` callback: every reportedip.com link printed through esc_url()
	 * in the admin goes to the page in the admin's language.
	 *
	 * @param string $good_url Escaped URL.
	 * @return string
	 * @since  3.0.9
	 */
	public static function localize_clean_url( $good_url ) {
		if ( ! is_admin() || false === strpos( (string) $good_url, 'reportedip.com' ) ) {
			return $good_url;
		}
		return self::localize_url( (string) $good_url );
	}

	/**
	 * Tag a reportedip.com link with its campaign source.
	 *
	 * reportedip.com counts clicks, sign-ups and revenue per source from the
	 * `rc` argument. The tag goes in front of an anchor, replaces an older
	 * tag and any `utm_*` argument, and stays off the API, feeds and legal
	 * pages. Links to other hosts come back unchanged. Plain PHP, so it
	 * works before WordPress has loaded its URL helpers.
	 *
	 * @param string $url    Link.
	 * @param string $source Campaign source.
	 * @return string
	 * @since  3.0.1
	 */
	public static function campaign_url( $url, $source = self::RC_PLUGIN ) {
		$url  = (string) $url;
		$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( 'reportedip.com' !== $host && 'www.reportedip.com' !== $host ) {
			return $url;
		}
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		if ( preg_match( self::CAMPAIGN_EXEMPT, '' === $path ? '/' : $path ) ) {
			return $url;
		}

		$fragment = '';
		$hash     = strpos( $url, '#' );
		if ( false !== $hash ) {
			$fragment = substr( $url, $hash );
			$url      = substr( $url, 0, $hash );
		}
		$query = '';
		$mark  = strpos( $url, '?' );
		if ( false !== $mark ) {
			$query = substr( $url, $mark + 1 );
			$url   = substr( $url, 0, $mark );
		}
		if ( '' === $path ) {
			$url .= '/';
		}

		$args = array();
		foreach ( '' === $query ? array() : explode( '&', $query ) as $pair ) {
			$name = strtolower( rawurldecode( (string) strtok( $pair, '=' ) ) );
			if ( 'rc' === $name || 0 === strpos( $name, 'utm_' ) ) {
				continue;
			}
			$args[] = $pair;
		}
		$args[] = 'rc=' . rawurlencode( $source );

		return $url . '?' . implode( '&', $args ) . $fragment;
	}

	/**
	 * One row per add-on feature. Keys equal the feature keys the add-on
	 * registers in the feature matrix; a gate in the repository keeps both
	 * lists identical. Built on call so the strings are translated.
	 *
	 * `community_only` is set on a feature that needs the Community Network
	 * (its matrix row has `local => false`), so a Local Shield site can say so.
	 *
	 * `section` is the registry section the feature belongs to, or one of
	 * {@see sections()} when the add-on brings the whole section.
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
				'description'    => __( 'A second factor by text message, delivered through the EU gateway, no contract with an SMS provider.', 'reportedip-hive' ),
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
				'description' => __( 'When a coordinated attack is detected, the limits tighten for an hour: 2 failed logins instead of 5 and a block threshold of 60 percent instead of 75.', 'reportedip-hive' ),
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
				'description' => __( 'The execution proof on WPForms, Gravity Forms, Forminator, Formidable, Elementor Forms, Divi, Ultimate Member and the EU Order Withdrawal Button form.', 'reportedip-hive' ),
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
	 * Sections that only the add-on fills, with the label and description
	 * the add-on gives them and the Protection-page tab they sit on. Without
	 * the add-on the Protection page shows them with their catalog rows, so
	 * the section and its anchor exist in both installations.
	 *
	 * @return array<string, array{label:string, description:string, tab:string}>
	 * @since  3.0.0
	 */
	public static function sections() {
		return array(
			'hardening_mode' => array(
				'label'       => __( 'Attack Response', 'reportedip-hive' ),
				'description' => __( 'What changes while a coordinated attack is running.', 'reportedip-hive' ),
				'tab'         => 'advanced',
			),
			'twofa_policies' => array(
				'label'       => __( 'Adaptive Step-Up', 'reportedip-hive' ),
				'description' => __( 'When a user who already passed the second factor is asked for it again.', 'reportedip-hive' ),
				'tab'         => 'advanced',
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
