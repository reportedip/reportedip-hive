import { execSync } from 'node:child_process';
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

function wp(args: string): string {
	return execSync(`docker compose -f ${MS_COMPOSE} exec -T ${MS_SERVICE} wp --allow-root ${args}`, {
		cwd: resolveWorkspaceRoot(),
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

function wpTolerant(args: string): string {
	try {
		return wp(args);
	} catch {
		return '';
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('network 2fa policies on a site page', () => {
	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		wp('network meta update 1 reportedip_hive_known_tier professional');
		wp(`network meta update 1 ${POLICY_KEY} '["editor"]'`);
	});

	test.afterAll(() => {
		wpTolerant(`network meta delete 1 ${POLICY_KEY}`);
		wpTolerant('network meta delete 1 reportedip_hive_known_tier');
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
});
