<?php
/**
 * Bundled WAF baseline ruleset (free floor).
 *
 * A deliberately narrow, false-positive-averse OWASP-Top-10 floor (CRS Paranoia
 * Level 1) so the free WAF blocks the obvious attacks and honours the
 * "protection is free" promise. The real depth and freshness — broader
 * signatures, PL2/PL3, obfuscation/bypass resistance, frequent updates — lives
 * in the PRO+ ruleset delivered by the reportedip.com API
 * ({@see ReportedIP_Hive_Rule_Sync}). The patterns here are anchored and
 * possessive/atomic where possible to stay ReDoS-safe.
 *
 * Each rule: id, group, pattern (PCRE without delimiters), paranoia, severity,
 * target (uri|body|ua|all).
 *
 * The `waf_xss_*` markup family covers injected HTML that carries no script and
 * no event handler, so the two classic XSS signatures never see it. A sanitiser
 * parser differential (`strip_tags()` accepts `< area`, KSES reads it as an
 * `<area>` element) lets such markup reach the page, where an `id`/`name`
 * attribute clobbers a JavaScript global and turns the site's own bundled
 * scripts into the payload — the CVE-2026-64638 chain. `waf_xss_login_markup`
 * closes the login surface by value range: `sanitize_user()` strips angle
 * brackets, so a `log`/`user_login` value containing one is never legitimate.
 * `waf_xss_tag_differential` detects the clobbering primitive itself and
 * therefore covers the bug class rather than one advisory. The two `_jsonp`
 * rules cover the Same-Origin-Method-Execution escalation, where the REST JSONP
 * callback carries property traversal instead of a plain function name.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(
	'key'     => 'waf',
	'version' => 0,
	'rules'   => array(
		array(
			'id'       => 'waf_sqli_union',
			'group'    => 'sql_injection',
			'pattern'  => '(?i)\bunion\b[\s\S]{0,80}?\bselect\b',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'all',
		),
		array(
			'id'       => 'waf_sqli_bool',
			'group'    => 'sql_injection',
			'pattern'  => '(?i)(?:\bor\b|\band\b)\s+[\'"\d][\s\S]{0,20}?=\s*[\'"\d][\s\S]{0,8}?(?:--|#|/\*)',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'all',
		),
		array(
			'id'       => 'waf_xss_script',
			'group'    => 'xss',
			'pattern'  => '(?i)<script[\s>]',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'all',
		),
		array(
			'id'       => 'waf_xss_handler',
			'group'    => 'xss',
			'pattern'  => '(?i)\bon(?:error|load|mouseover|focus|click)\s*=',
			'paranoia' => 1,
			'severity' => 'medium',
			'target'   => 'all',
		),
		array(
			'id'       => 'waf_xss_login_markup',
			'group'    => 'xss',
			'pattern'  => '(?i)(?:^|[\s&])(?:log|user_login)=(?:(?!\s[a-z_][\w-]*=)[^&\r\n]){0,160}?[<>]',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'body',
		),
		array(
			'id'       => 'waf_xss_tag_differential',
			'group'    => 'xss',
			'pattern'  => '(?i)<\s+[a-z][a-z0-9]{0,14}\s+(?:[a-z-]{1,20}\s*=[^>]{0,60}\s+)?(?:id|name)\s*=',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'all',
		),
		array(
			'id'       => 'waf_xss_jsonp_some',
			'group'    => 'xss',
			'pattern'  => '(?i)[?&]_jsonp=[\w.]*(?:\b(?:opener|parent|top|frames|self|window|document|location)\b|\.(?:click|submit|focus|open|reload|assign|replace)\b)',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'uri',
		),
		array(
			'id'       => 'waf_xss_jsonp_sink',
			'group'    => 'xss',
			'pattern'  => '(?i)[?&]_jsonp=(?:alert|prompt|confirm|eval)\b',
			'paranoia' => 1,
			'severity' => 'medium',
			'target'   => 'uri',
		),
		array(
			'id'       => 'waf_traversal',
			'group'    => 'path_traversal',
			'pattern'  => '(?:\.\./|\.\.\\\\|%2e%2e[/\\\\]|\.\.%2f)',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'all',
		),
		array(
			'id'       => 'waf_file_probe',
			'group'    => 'file_probe',
			'pattern'  => '(?i)(?:wp-config\.php(?:\.(?:bak|old|save|orig|txt))|/\.env(?:\.|$)|/\.git/config)',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'uri',
		),
		array(
			'id'       => 'waf_phpunit_evalstdin',
			'group'    => 'file_probe',
			'pattern'  => '(?i)/phpunit/[\s\S]{0,80}?eval-stdin\.php',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'uri',
		),
		array(
			'id'       => 'waf_cmd_inject',
			'group'    => 'cmd_injection',
			'pattern'  => '(?i)[;|`]\s*(?:cat|wget|curl|nc|bash|sh|powershell|whoami|id)\b',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'all',
		),
		array(
			'id'       => 'waf_scanner_ua',
			'group'    => 'scanner_ua',
			'pattern'  => '(?i)\b(?:sqlmap|nikto|nessus|acunetix|nuclei|wpscan|dirbuster|gobuster)\b',
			'paranoia' => 1,
			'severity' => 'medium',
			'target'   => 'ua',
		),
		array(
			'id'       => 'waf_rest_batch_desync',
			'group'    => 'rest_abuse',
			'pattern'  => '(?i)"path"\s*:\s*"(?:/{2,}(?![a-z0-9])|[a-z][a-z0-9+.\-]*:/{2,}(?:[:/?#]|"))',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'body',
		),
		array(
			'id'       => 'waf_rest_batch_nested',
			'group'    => 'rest_abuse',
			'pattern'  => '(?i)"body"\s*:\s*\{[^{}]{0,120}?"requests"\s*:\s*\[',
			'paranoia' => 1,
			'severity' => 'high',
			'target'   => 'body',
		),
	),
);
