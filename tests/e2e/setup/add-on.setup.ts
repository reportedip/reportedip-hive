/**
 * Setup and teardown of a free run with the add-on active
 * (`RIP_E2E_WITH_PRO=1`, see playwright.config.ts).
 *
 * One file serves four projects; the project name says which stack and
 * which direction: `add-on-on-<stack>` activates the add-on before the
 * stack's specs, `add-on-off-<stack>` deactivates it again afterwards, so
 * a later free run sees the free plugin alone. Single-site runs in the
 * container of the free suite, multisite through the multisite compose
 * file, network-wide.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     3.0.0
 */

import { execFileSync } from 'node:child_process';
import { test, expect } from '@playwright/test';
import { WP_CONTAINER } from '../fixtures/wp';
import { workspaceRoot } from '../fixtures/workspace';

const SLUG = 'reportedip-hive-pro';

function cli(multisite: boolean, ...args: string[]): string {
	const argv = multisite
		? ['compose', '-f', 'docker-compose.multisite.yml', 'exec', '-T', 'wordpress-ms', 'wp', '--allow-root', ...args, '--network']
		: ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args];
	return execFileSync('docker', argv, { cwd: workspaceRoot(), encoding: 'utf8' }).toString().trim();
}

function isActive(multisite: boolean): boolean {
	try {
		cli(multisite, 'plugin', 'is-active', SLUG);
		return true;
	} catch {
		return false;
	}
}

test('the add-on has the state this project asks for', () => {
	const name = test.info().project.name;
	const multisite = name.endsWith('multisite');
	const on = name.startsWith('add-on-on-');
	cli(multisite, 'plugin', on ? 'activate' : 'deactivate', SLUG);
	expect(isActive(multisite)).toBe(on);
});
