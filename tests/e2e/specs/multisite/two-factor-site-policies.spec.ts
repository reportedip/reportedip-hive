import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Adaptive 2FA policies on a network (Professional, since 2.1.51): the matrix
 * is a Super Admin decision, so the site-level 2FA page shows it read-only.
 *
 * The page is opened on the network's main site rather than through
 * `/site-a/wp-admin/`: the dev stack's subdir rewrite bounces sub-site admin
 * URLs back to themselves. Both are the same render path — the site-admin
 * menu is registered per site, network admin has its own pages.
 *
 * Serial: the spec mutates shared network state on the long-lived stack.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';
const POLICY_KEY = 'reportedip_hive_2fa_policy_new_ip';

function resolveWorkspaceRoot(): string {
	return new URL('../../../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
}

/**
 * Run WP-CLI in the multisite container. Arguments travel as argv, never
 * through a shell: a JSON value like `["editor"]` keeps its quotes on both
 * cmd.exe and sh.
 */
function wp(...args: string[]): string {
	return execFileSync(
		'docker',
		['compose', '-f', MS_COMPOSE, 'exec', '-T', MS_SERVICE, 'wp', '--allow-root', ...args],
		{ cwd: resolveWorkspaceRoot(), encoding: 'utf8' }
	)
		.toString()
		.trim();
}

/**
 * Run a PHP snippet in the container. Statements are joined with a space so
 * the whole batch is one argv entry and one `docker compose exec` call.
 */
function wpEval(statements: string[]): string {
	return wp('eval', statements.join(' '));
}

test.describe.configure({ mode: 'serial' });

test.describe('network 2fa policies on a site page', () => {
	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		wpEval([
			'foreach (ReportedIP_Hive_Two_Factor_Policies::TRIGGERS as $t) { ReportedIP_Hive_Option_Routing::delete(ReportedIP_Hive_Two_Factor_Policies::option_key($t)); }',
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_known_tier', 'professional');",
			"delete_transient('reportedip_hive_api_status');",
			`ReportedIP_Hive_Option_Routing::set('${POLICY_KEY}', wp_json_encode(array('editor')));`,
			"echo 'SEEDED';",
		]);
	});

	test.afterAll(() => {
		wpEval([
			'foreach (ReportedIP_Hive_Two_Factor_Policies::TRIGGERS as $t) { ReportedIP_Hive_Option_Routing::delete(ReportedIP_Hive_Two_Factor_Policies::option_key($t)); }',
			"ReportedIP_Hive_Option_Routing::delete('reportedip_hive_known_tier');",
			"echo 'CLEANED';",
		]);
	});

	test('the site 2FA page shows the network policy read-only', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-site-2fa');

		const block = page.locator('.rip-settings-section', {
			hasText: 'Adaptive 2FA triggers (network policy)',
		});

		await expect(block).toBeVisible();
		await expect(block.locator('.rip-network-state li')).toHaveCount(7);
		await expect(block.locator('input[type="checkbox"]')).toHaveCount(0);
	});

	test('the block names the armed role and marks the rest off', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-site-2fa');

		const list = page.locator('.rip-settings-section', {
			hasText: 'Adaptive 2FA triggers (network policy)',
		}).locator('.rip-network-state');

		const armed = list.locator('li', { hasText: 'New IP address' });
		await expect(armed.locator('.rip-badge--info')).toHaveText('Editor');
		await expect(armed.locator('.rip-badge--neutral')).toHaveCount(0);

		// Every other trigger stays unconfigured, so six rows read "off".
		await expect(list.locator('li .rip-badge--neutral')).toHaveCount(6);
	});
});
