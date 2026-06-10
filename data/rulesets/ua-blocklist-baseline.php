<?php
/**
 * Bundled user-agent blocklist baseline ruleset (free floor).
 *
 * Core scanner / exploitation-tool user-agent tokens. The PRO+ ruleset from the
 * API extends this with a much wider, frequently-updated set. Matching is
 * case-insensitive substring on the request user agent. See
 * {@see ReportedIP_Hive_Rule_Sync}.
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
	'key'     => 'ua_blocklist',
	'version' => 0,
	'rules'   => array(
		'sqlmap',
		'nikto',
		'nessus',
		'acunetix',
		'nuclei',
		'wpscan',
		'dirbuster',
		'gobuster',
		'masscan',
		'zgrab',
	),
);
