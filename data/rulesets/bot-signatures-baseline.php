<?php
/**
 * Bundled verified-bot baseline ruleset (free floor).
 *
 * A small set of well-known crawlers mapped to their valid forward-confirmed
 * reverse-DNS suffixes. The free floor verifies the major search engines via
 * FCrDNS; the PRO+ ruleset from the API adds the official Google/Bing IP-range
 * feeds (DNS-free primary verification) and a much broader, frequently-updated
 * bot list. See {@see ReportedIP_Hive_Rule_Sync}.
 *
 * Each rule: ua (case-insensitive token), domains (valid PTR suffixes),
 * ranges (CIDR list, empty in the baseline — supplied by the API feed).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(
	'key'     => 'bot_signatures',
	'version' => 0,
	'rules'   => array(
		array(
			'ua'      => 'googlebot',
			'domains' => array( '.googlebot.com', '.google.com' ),
			'ranges'  => array(),
		),
		array(
			'ua'      => 'bingbot',
			'domains' => array( '.search.msn.com' ),
			'ranges'  => array(),
		),
		array(
			'ua'      => 'duckduckbot',
			'domains' => array( '.duckduckgo.com' ),
			'ranges'  => array(),
		),
		array(
			'ua'      => 'yandexbot',
			'domains' => array( '.yandex.com', '.yandex.net', '.yandex.ru' ),
			'ranges'  => array(),
		),
		array(
			'ua'      => 'applebot',
			'domains' => array( '.applebot.apple.com' ),
			'ranges'  => array(),
		),
	),
);
