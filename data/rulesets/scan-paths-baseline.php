<?php
/**
 * Bundled scan/honeypot-path baseline ruleset (free floor).
 *
 * Core bait paths that only a scanner would request. The PRO+ ruleset from the
 * API extends this with a much wider, frequently-updated set. These feed the
 * existing scan detector. See {@see ReportedIP_Hive_Rule_Sync}.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(
	'key'     => 'scan_paths',
	'version' => 0,
	'rules'   => array(
		'/.env',
		'/.git/config',
		'/wp-config.php.bak',
		'/wp-config.old.php',
		'/.aws/credentials',
		'/config.php.bak',
		'/backup.sql',
		'/.ssh/id_rsa',
		'/phpinfo.php',
		'/.DS_Store',
	),
);
