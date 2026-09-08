import { execSync } from 'node:child_process';
import type { Page } from '@playwright/test';
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
 * The block record lives in user meta, which a network shares across every
 * site. The sub-site half of the proof runs through WP-CLI booted on that
 * sub-site (`--url`) rather than through its login form: the stack's
 * subdirectory rewrite does not hand `/site-a/wp-login.php` to wp-login.php,
 * so that URL answers with a canonical redirect to itself and no browser can
 * submit the form there.
 *
 * Serial: the spec mutates shared network state on the long-lived stack.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';
// Network usernames may only contain lowercase letters and digits.
const TEST_USER = 'ripe2eblockedms';
const TEST_PASS = 'RipE2eBlockMs-2151';
const SUBSITE_PATH = '/site-a/';
const BLOCK_MESSAGE = 'Offboarded during the network E2E run.';
const DEFAULT_BLOCK_TEXT = 'This account has been blocked.';

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

/**
 * Drop and recreate the throwaway network subscriber so every run starts from
 * an unblocked account with a password this spec knows.
 */
function provisionTestUser(): number {
	wpTolerant(`user delete ${TEST_USER} --network --yes`);
	return Number(
		wp(`user create ${TEST_USER} ${TEST_USER}@example.org --role=subscriber --user_pass=${TEST_PASS} --porcelain`)
	);
}

/**
 * Submit the login form. Does not wait for a result — the caller decides
 * whether it expects wp-admin or an error notice.
 */
async function submitLogin(page: Page, login: string, pass: string, loginPath = '/wp-login.php'): Promise<void> {
	await page.goto(loginPath);
	await page.fill('#user_login', login);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
}

/**
 * The `rip-toggle` checkbox is visually replaced by a CSS slider, so the input
 * itself is not "visible" to Playwright. Drive it by clicking the wrapping
 * label; read state straight off the (hidden) input.
 */
async function setToggle(page: Page, inputSelector: string, desired: boolean): Promise<void> {
	const input = page.locator(inputSelector);
	if ((await input.isChecked()) !== desired) {
		await page.locator(`label.rip-toggle:has(${inputSelector})`).click();
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('network user blocking and sessions', () => {
	let userId = 0;

	// Every test here signs the administrator in from a fresh context and then
	// loads a network-admin page; on this host that regularly passes the 120 s
	// default before the first assertion runs.
	test.beforeEach(() => {
		test.setTimeout(240_000);
	});

	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		userId = provisionTestUser();
		wpTolerant('network meta delete 1 reportedip_hive_known_tier');
		// The spec drives a deliberate failed sign-in; the stock threshold of 5
		// per 15 minutes is shared with every other spec on this long-lived
		// stack, and tipping it would IP-block the runner mid-suite.
		wp('network meta update 1 reportedip_hive_failed_login_threshold 50');
	});

	test.afterAll(() => {
		wpTolerant(`user delete ${TEST_USER} --network --yes`);
		wpTolerant('network meta delete 1 reportedip_hive_known_tier');
		wpTolerant('network meta delete 1 reportedip_hive_failed_login_threshold');
	});

	test('network sessions page is locked below Business', async ({ page }) => {
		wpTolerant('network meta delete 1 reportedip_hive_known_tier');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/users.php?page=reportedip-hive-sessions');

		await expect(page.locator('.rip-header__title')).toContainText('Sessions');
		await expect(page.locator('.rip-tier-badge--business')).toBeVisible();
		await expect(page.locator('#rip-sessions-form')).toHaveCount(0);
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
		await expect(page.locator('th#rip_account, td.rip_account').first()).toBeVisible();
	});

	test('network user edit screen carries the account access card', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`/wp-admin/network/user-edit.php?user_id=${userId}`);

		await expect(page.locator('#reportedip-hive-account-access')).toBeVisible();
		await expect(page.locator('input[name="rip_block_user"]')).toBeVisible();
	});

	test('a block made in Network Admin refuses the sign-in', async ({ page, browser }) => {
		await loginAsAdmin(page);
		await page.goto(`/wp-admin/network/user-edit.php?user_id=${userId}`);
		await expect(page.locator('#reportedip-hive-account-access')).toBeVisible();

		await setToggle(page, 'input[name="rip_block_user"]', true);
		await page.fill('#rip_block_message', BLOCK_MESSAGE);
		await page.click('#submit');
		// The core "User updated." notice is the proof the profile POST came
		// back. `waitForURL` on the `updated` query arg is not used: it did not
		// resolve on this stack even with the notice already on screen.
		await expect(page.locator('body')).toContainText('User updated.', { timeout: 90_000 });
		await expect(page.locator('input[name="rip_block_user"]')).toBeChecked();

		const visitor = await browser.newContext();
		const guest = await visitor.newPage();
		await submitLogin(guest, TEST_USER, TEST_PASS);

		await expect(guest.locator('#login_error')).toContainText(DEFAULT_BLOCK_TEXT);
		await expect(guest.locator('#login_error')).toContainText(BLOCK_MESSAGE);
		expect(new URL(guest.url()).pathname).toContain('wp-login.php');
		await visitor.close();
	});

	test('the network block is enforced on a sub-site', () => {
		const base = (test.info().project.use.baseURL ?? 'http://localhost:8090').replace(/\/$/, '');
		const code = wp(
			`eval "$u=wp_authenticate('${TEST_USER}','${TEST_PASS}'); echo is_wp_error($u) ? $u->get_error_code() : 'authenticated';" ` +
				`--url=${base}${SUBSITE_PATH}`
		);

		expect(code).toBe('reportedip_user_blocked');
	});
});
