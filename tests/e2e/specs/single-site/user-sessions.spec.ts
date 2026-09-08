import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Account blocking and the session manager (Business, since 2.1.51).
 *
 * The tier is driven through `reportedip_hive_known_tier`, the durable
 * fallback the mode manager reads when no API status transient is present.
 * The API mock also carries a `business` scenario (`echo business >
 * profiles/mock-scenario.txt`) for driving the same state through a real
 * verify-key round trip.
 *
 * Serial: the spec mutates the stack's stored tier.
 */

const TEST_USER = 'rip_e2e_blocked';

function resolveWorkspaceRoot(): string {
	return new URL('../../../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
}

function wp(args: string): string {
	return execSync(`docker compose exec -T wordpress wp --allow-root ${args}`, {
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

test.describe('user blocking and sessions', () => {
	let userId = 0;

	test.beforeAll(() => {
		resetAdminBaseline();
		userId = ensureTestUser();
		wpTolerant('option delete reportedip_hive_known_tier');
	});

	test.afterAll(() => {
		wpTolerant('option delete reportedip_hive_known_tier');
	});

	test('sessions page is locked below Business', async ({ page }) => {
		wpTolerant('option delete reportedip_hive_known_tier');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/users.php?page=reportedip-hive-sessions');

		await expect(page.locator('.rip-header__title')).toContainText('Sessions');
		await expect(page.locator('.rip-tier-badge--business')).toBeVisible();
		await expect(page.locator('#rip-sessions-form')).toHaveCount(0);
	});

	test('sessions table renders on Business', async ({ page }) => {
		wp('option update reportedip_hive_known_tier business');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/users.php?page=reportedip-hive-sessions');

		await expect(page.locator('#rip-sessions-form')).toBeVisible();
		await expect(page.locator('table.rip-table')).toBeVisible();
	});

	test('users list loads without PHP notices', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/users.php');

		const body = (await page.locator('body').innerText()) ?? '';
		expect(body).not.toContain('Fatal error');
		expect(body).not.toContain('Warning:');
		expect(body).not.toContain('Notice:');
		await expect(page.locator('th#rip_account, td.rip_account').first()).toBeVisible();
	});

	test('user edit screen carries the account access card', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`/wp-admin/user-edit.php?user_id=${userId}`);

		await expect(page.locator('#reportedip-hive-account-access')).toBeVisible();
		await expect(page.locator('input[name="rip_block_user"]')).toBeVisible();
	});
});
