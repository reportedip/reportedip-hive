/**
 * Where the Docker workspace lives.
 *
 * The compose files sit in the workspace root, which is a different number
 * of directories above this file depending on the checkout layout (the
 * former `dev/` clone versus the monorepo under `repo/plugins/`). The
 * runner exports `RIP_E2E_WORKSPACE`; without it the search walks upwards
 * until a `docker-compose.yml` is found.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     3.0.0
 */

import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Absolute path of the workspace root (the directory holding docker-compose.yml). */
export function workspaceRoot(): string {
	const fromEnv = process.env.RIP_E2E_WORKSPACE;
	if (fromEnv && existsSync(join(fromEnv, 'docker-compose.yml'))) {
		return resolve(fromEnv);
	}
	let dir = dirname(fileURLToPath(import.meta.url));
	for (let i = 0; i < 10; i++) {
		if (existsSync(join(dir, 'docker-compose.yml'))) {
			return dir;
		}
		const parent = dirname(dir);
		if (parent === dir) {
			break;
		}
		dir = parent;
	}
	throw new Error('ReportedIP Hive E2E: workspace root with docker-compose.yml not found; set RIP_E2E_WORKSPACE.');
}

/** Absolute path of a compose file in the workspace root. */
export function composeFile(name: 'docker-compose.yml' | 'docker-compose.multisite.yml'): string {
	return join(workspaceRoot(), name);
}
