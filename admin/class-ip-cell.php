<?php
/**
 * Shared renderer for IP address table cells with copy, lookup and external-link actions.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.41
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the reusable IP cell used across the admin list tables and dashboard.
 *
 * The markup mirrors the copy/lookup button patterns the delegated handlers in
 * `assets/js/admin.js` bind to (`.copy-ip`, `.lookup-ip`), so every call site
 * shares one renderer instead of duplicating the sprintf blocks.
 *
 * @since 2.1.41
 */
final class ReportedIP_Hive_IP_Cell {

	/**
	 * Build the public detail URL for an IP address on reportedip.com.
	 *
	 * @param string $ip IP address.
	 * @return string
	 * @since  2.1.41
	 */
	public static function external_url( $ip ) {
		return apply_filters(
			'reportedip_hive_external_url',
			REPORTEDIP_HIVE_SITE_URL . '/ip/' . rawurlencode( $ip ) . '/',
			'ip_detail'
		);
	}

	/**
	 * Render the escaped IP cell markup.
	 *
	 * CIDR entries force lookup and external off because both the community
	 * lookup and the public detail page operate on single addresses only.
	 *
	 * @param string $ip   IP address or CIDR range.
	 * @param array  $opts Options: 'strong' (bool, default false), 'copy' (bool,
	 *                     default true), 'lookup' (bool, default true),
	 *                     'external' (bool, default true).
	 * @return string Escaped HTML.
	 * @since  2.1.41
	 */
	public static function render( $ip, array $opts = array() ) {
		$opts = array_merge(
			array(
				'strong'   => false,
				'copy'     => true,
				'lookup'   => true,
				'external' => true,
			),
			$opts
		);

		if ( false !== strpos( $ip, '/' ) ) {
			$opts['lookup']   = false;
			$opts['external'] = false;
		}

		$code = sprintf(
			'<code class="ip-address" title="%s">%s</code>',
			esc_attr__( 'Click to copy', 'reportedip-hive' ),
			esc_html( $ip )
		);

		if ( $opts['strong'] ) {
			$code = '<strong>' . $code . '</strong>';
		}

		$html = '<span class="rip-ip-cell">' . $code;

		if ( $opts['copy'] ) {
			$html .= sprintf(
				'<button type="button" class="button-link copy-ip" data-ip="%s" title="%s"><span class="dashicons dashicons-clipboard" aria-hidden="true"></span></button>',
				esc_attr( $ip ),
				esc_attr__( 'Copy IP', 'reportedip-hive' )
			);
		}

		if ( $opts['lookup'] ) {
			$html .= sprintf(
				'<button type="button" class="button-link lookup-ip" data-ip="%s" title="%s"><span class="dashicons dashicons-search" aria-hidden="true"></span></button>',
				esc_attr( $ip ),
				esc_attr__( 'Lookup IP', 'reportedip-hive' )
			);
		}

		if ( $opts['external'] ) {
			$label = sprintf(
				/* translators: %s = IP address. */
				__( 'View %s on reportedip.com (opens in a new tab)', 'reportedip-hive' ),
				$ip
			);

			$html .= sprintf(
				'<a class="button-link rip-ip-cell__external" href="%s" target="_blank" rel="noopener noreferrer" title="%s" aria-label="%s"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>',
				esc_url( self::external_url( $ip ) ),
				esc_attr( $label ),
				esc_attr( $label )
			);
		}

		return $html . '</span>';
	}
}
