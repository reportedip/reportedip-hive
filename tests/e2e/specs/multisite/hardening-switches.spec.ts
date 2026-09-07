import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The attack-surface switches are network state: one network option closes
 * xmlrpc.php on every sub-site, and the settings section lives on the Network
 * Admin firewall page.
 *
 * Serial: the spec mutates shared network state on the long-lived stack.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';

function resolveWorkspaceRoot(): string {
	return new URL('../../../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
}

function wp(args: string): string {
	return execSync(
		`docker compose -f ${MS_COMPOSE} exec -T ${MS_SERVICE} wp --allow-root ${args}`,
		{ cwd: resolveWorkspaceRoot(), encoding: 'utf8' }
	)
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

test.describe('attack surface switches on a network', () => {
	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		wpTolerant('network meta delete 1 reportedip_hive_disable_xmlrpc');
	});

	test.afterAll(() => {
		wpTolerant('network meta delete 1 reportedip_hive_disable_xmlrpc');
	});

	/**
	 * One sitemeta value closes the network's single xmlrpc.php endpoint,
	 * which serves every sub-site. The prefixed `/site-a/xmlrpc.php` form is
	 * deliberately not asserted: in this subdir stack the prefix-stripping
	 * rewrite is absent, so that path answers 404 either way and the check
	 * would prove nothing.
	 */
	test('one network option closes xmlrpc.php for the whole network', async ({ request }) => {
		wp('network meta update 1 reportedip_hive_disable_xmlrpc 1');

		const denied = await request.post('/xmlrpc.php', { failOnStatusCode: false });
		expect([403, 404]).toContain(denied.status());

		const subsite = await request.get('/site-a/', { failOnStatusCode: false });
		expect(subsite.status()).toBe(200);

		wp('network meta update 1 reportedip_hive_disable_xmlrpc 0');
		const open = await request.post('/xmlrpc.php', { failOnStatusCode: false });
		expect(open.status()).toBe(200);
	});

	test('network admin sees the attack-surface section', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/admin.php?page=reportedip-hive-firewall&tab=hardening');

		await expect(page.locator('#rip-attack-surface-form')).toBeVisible();
		await expect(page.locator('#rip-rest-access-mode')).toBeVisible();
	});
});
