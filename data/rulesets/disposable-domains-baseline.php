<?php
/**
 * Bundled disposable-email baseline ruleset (free floor).
 *
 * A short list of the most common throwaway-mail domains. The PRO+ ruleset from
 * the API delivers the live, frequently-updated list (thousands of domains,
 * allowlist-cleaned) plus the privacy-relay classification. Privacy relays
 * (Apple Hide My Email, Firefox Relay, …) are intentionally NOT listed here —
 * they are legitimate and must not be blocked. See
 * {@see ReportedIP_Hive_Rule_Sync}.
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
	'key'     => 'disposable_domains',
	'version' => 0,
	'rules'   => array(
		'mailinator.com',
		'temp-mail.org',
		'tempmail.com',
		'guerrillamail.com',
		'10minutemail.com',
		'throwawaymail.com',
		'yopmail.com',
		'getnada.com',
		'trashmail.com',
		'sharklasers.com',
		'maildrop.cc',
		'dispostable.com',
	),
);
