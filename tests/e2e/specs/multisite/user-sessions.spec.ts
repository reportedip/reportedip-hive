import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Account blocking and the session manager on a network (Business, 2.1.51).
 *
 * Users and sessions are network-global, so the manager lives in Network
 * Admin under Users. The tier is driven through the sitemeta fallback
 * `reportedip_hive_known_tier`; the API mock's `business` scenario drives the
 * same state through a verify-key round trip.
 *
 * Serial: the spec mutates shared network state on the long-lived stack.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';
// Network usernames may only contain lowercase letters and digits.
const TEST_USER = 'ripe2eblockedms';

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

function ensureTestUser(): number {
	const existing = wpTolerant(`user get ${TEST_USER} --field=ID`);
	if (/^\d+$/.test(existing)) {
		return Number(existing);
	}
	wp(`user create ${TEST_USER} ${TEST_USER}@example.org --role=subscriber --porcelain`);
	return Number(wp(`user get ${TEST_USER} --field=ID`));
}

test.describe.configure({ mode: 'serial' });

test.describe('network user blocking and sessions', () => {
	let userId = 0;

	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		userId = ensureTestUser();
		wpTolerant('network meta delete 1 reportedip_hive_known_tier');
	});

	test.afterAll(() => {
		wpTolerant('network meta delete 1 reportedip_hive_known_tier');
	});

	test('network sessions page is locked below Business', async ({ page }) => {
		wpTolerant('network meta delete 1 reportedip_hive_known_tier');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/users.php?page=reportedip-hive-sessions');

		await expect(page.locator('.rip-header__title')).toContainText('Sessions');
		await expect(page.locator('.rip-tier-badge--business')).toBeVisible();
	});

	test('network sessions table renders on Business', async ({ page }) => {
		wp('network meta update 1 reportedip_hive_known_tier business');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/users.php?page=reportedip-hive-sessions');

		await expect(page.locator('#rip-sessions-form')).toBeVisible();
		await expect(page.locator('table.rip-table')).toBeVisible();
	});

	test('network users list loads without PHP notices', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/users.php');

		const body = (await page.locator('body').innerText()) ?? '';
		expect(body).not.toContain('Fatal error');
		expect(body).not.toContain('Warning:');
		expect(body).not.toContain('Notice:');
	});

	test('network user edit screen carries the account access card', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`/wp-admin/network/user-edit.php?user_id=${userId}`);

		await expect(page.locator('#reportedip-hive-account-access')).toBeVisible();
	});
});
