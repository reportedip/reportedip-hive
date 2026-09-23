/**
 * WP-CLI access to the single-site container for specs that read or shape
 * plugin state directly.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.64
 */

import { execFileSync } from 'node:child_process';

export const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

/**
 * Run a WP-CLI command inside the container. Uses an argument vector so PHP
 * snippets survive the Windows shell unquoted.
 */
export function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], {
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

/**
 * Run one PHP snippet in the container. Batch a whole job into one call: a
 * single `docker exec` costs about five seconds here.
 */
export function php(code: string): string {
	return wp('eval', code.replace(/\s*\n\s*/g, ' ').trim());
}

export function phpTolerant(code: string): string {
	try {
		return php(code);
	} catch {
		return '';
	}
}

/** Create or drop a flag file the dev-stack mu-plugins watch. */
export function flag(name: string, on: boolean): void {
	execFileSync('docker', [
		'exec',
		WP_CONTAINER,
		'sh',
		'-c',
		on ? `touch /profiles/${name}` : `rm -f /profiles/${name}`,
	]);
}
