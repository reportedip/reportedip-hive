<?php
/**
 * Baseline Tor exit-node list: deliberately empty.
 *
 * Tor blocking is a Professional feature and the exit-node set rotates by
 * the hour, so no static snapshot ships with the plugin — it would be stale
 * on arrival and block re-assigned addresses. PRO sites receive the live
 * list through the signed ruleset sync (`tor_exits`, refreshed twice a day
 * server-side); without a synced ruleset the feature simply matches nothing.
 *
 * Rule shape: flat IP/CIDR strings as delivered by the feed
 * (e.g. `185.220.101.34/32`, IPv6 as `/128`).
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

return array(
	'key'     => 'tor_exits',
	'version' => 0,
	'rules'   => array(),
);
