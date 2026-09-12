import { execSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect, loginAsAdmin, ADMIN_USER } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { FORGET_CACHED_TIER_CLI } from '../../fixtures/tier';

/**
 * Account blocking and the session manager (Business, since 2.1.51).
 *
 * The tier is driven through `reportedip_hive_known_tier`, the durable
 * fallback the mode manager reads when no API status transient is present.
 * The API mock also carries a `business` scenario (`echo business >
 * profiles/mock-scenario.txt`) for driving the same state through a real
 * verify-key round trip.
 *
 * The behavioural half of the suite runs against a throwaway subscriber whose
 * password this spec owns, so the block can be proven the only way that
 * counts: a real sign-in attempt in a browser context that carries no admin
 * cookie. Sessions are read straight out of the `session_tokens` user meta,
 * the same store `ReportedIP_Hive_User_Sessions` reads.
 *
 * Serial: the spec mutates the stack's stored tier and one shared account.
 */

const TEST_USER = 'rip_e2e_blocked';
const TEST_PASS = 'RipE2eBlock-2151';
const BLOCK_MESSAGE = 'Offboarded during the E2E run.';
const DEFAULT_BLOCK_TEXT = 'This account has been blocked.';

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

/**
 * Drop and recreate the throwaway subscriber so every run starts from an
 * unblocked, session-free account with a password this spec knows.
 */
function provisionTestUser(): number {
	wpTolerant(`user delete ${TEST_USER} --yes`);
	return Number(
		wp(`user create ${TEST_USER} ${TEST_USER}@example.org --role=subscriber --user_pass=${TEST_PASS} --porcelain`)
	);
}

/**
 * Verifier keys of the live sessions of one user. Empty when core has removed
 * the meta entirely, which is what `destroy_all()` does.
 */
function sessionVerifiers(userId: number): string[] {
	const raw = wpTolerant(`user meta get ${userId} session_tokens --format=json`);
	if (!raw.startsWith('{')) {
		return [];
	}
	try {
		return Object.keys(JSON.parse(raw) as Record<string, unknown>);
	} catch {
		return [];
	}
}

/**
 * The result notice of a bulk action, isolated from any other plugin notice
 * that may be on the same screen.
 */
function resultNotice(page: Page, needle: RegExp) {
	return page.locator('.rip-notice__body').filter({ hasText: needle });
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

/**
 * Open the account card of the test user, set the block toggle and save.
 */
async function saveBlockState(page: Page, userId: number, blocked: boolean, message = ''): Promise<void> {
	await page.goto(`/wp-admin/user-edit.php?user_id=${userId}`);
	await expect(page.locator('#reportedip-hive-account-access')).toBeVisible();

	await setToggle(page, 'input[name="rip_block_user"]', blocked);
	if (blocked) {
		await page.fill('#rip_block_message', message);
	}

	await page.click('#submit');
	// The core "User updated." notice is the proof the profile POST came back;
	// `waitForURL` on the `updated` query arg proved unreliable on these stacks.
	await expect(page.locator('body')).toContainText('User updated.', { timeout: 90_000 });
}

test.describe.configure({ mode: 'serial' });

test.describe('user blocking and sessions', () => {
	let userId = 0;

	// Every test here signs a user in from a fresh context and then loads a
	// users or sessions screen; on this host that regularly passes the 120 s
	// default before the first assertion runs.
	test.beforeEach(() => {
		test.setTimeout(240_000);
	});

	test.beforeAll(() => {
		resetAdminBaseline();
		userId = provisionTestUser();
		wp('option update reportedip_hive_known_tier business');
		FORGET_CACHED_TIER_CLI.forEach((cmd) => wpTolerant(cmd));
		// The spec drives deliberate failed sign-ins; the stock threshold of 5
		// per 15 minutes is shared with every other spec on this long-lived
		// stack, and tipping it would IP-block the runner mid-suite.
		wp('option update reportedip_hive_failed_login_threshold 50');
	});

	test.afterAll(() => {
		wpTolerant(`user delete ${TEST_USER} --yes`);
		wpTolerant('option delete reportedip_hive_known_tier reportedip_hive_failed_login_threshold');
		FORGET_CACHED_TIER_CLI.forEach((cmd) => wpTolerant(cmd));
	});

	test('sessions page is locked below Business', async ({ page }) => {
		wpTolerant('option delete reportedip_hive_known_tier');
		FORGET_CACHED_TIER_CLI.forEach((cmd) => wpTolerant(cmd));
		await loginAsAdmin(page);
		await page.goto('/wp-admin/users.php?page=reportedip-hive-sessions');

		await expect(page.locator('.rip-header__title')).toContainText('Sessions');
		await expect(page.locator('.rip-tier-badge--business')).toBeVisible();
		await expect(page.locator('#rip-sessions-form')).toHaveCount(0);
	});

	test('sessions table renders on Business', async ({ page }) => {
		wp('option update reportedip_hive_known_tier business');
		FORGET_CACHED_TIER_CLI.forEach((cmd) => wpTolerant(cmd));
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

	test('blocking through the profile card ends every session of the account', async ({ page, browser }) => {
		const visitor = await browser.newContext();
		const guest = await visitor.newPage();
		await submitLogin(guest, TEST_USER, TEST_PASS);
		await guest.waitForURL((url) => url.pathname.includes('/wp-admin/'));
		await visitor.close();

		expect(sessionVerifiers(userId).length).toBeGreaterThan(0);

		await loginAsAdmin(page);
		await saveBlockState(page, userId, true, BLOCK_MESSAGE);
		await expect(page.locator('input[name="rip_block_user"]')).toBeChecked();

		expect(sessionVerifiers(userId)).toEqual([]);
	});

	test('a blocked account cannot sign in and is shown the operator message', async ({ browser }) => {
		const visitor = await browser.newContext();
		const guest = await visitor.newPage();
		await submitLogin(guest, TEST_USER, TEST_PASS);

		await expect(guest.locator('#login_error')).toContainText(DEFAULT_BLOCK_TEXT);
		await expect(guest.locator('#login_error')).toContainText(BLOCK_MESSAGE);
		expect(new URL(guest.url()).pathname).toContain('wp-login.php');
		await visitor.close();
	});

	test('the Blocked view lists exactly the blocked account', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/users.php?rip_blocked=1');

		await expect(page.locator('li.rip_blocked a')).toContainText('Blocked');
		await expect(page.locator('li.rip_blocked a .count')).toHaveText('(1)');

		const rows = page.locator('#the-list tr');
		await expect(rows).toHaveCount(1);
		await expect(rows.first().locator('.column-username')).toContainText(TEST_USER);
		await expect(rows.first().locator('td.rip_account .rip-badge--danger')).toHaveText('Blocked');
	});

	test('unblocking through the profile card restores the sign-in', async ({ page, browser }) => {
		await loginAsAdmin(page);
		await saveBlockState(page, userId, false);
		await expect(page.locator('input[name="rip_block_user"]')).not.toBeChecked();

		const visitor = await browser.newContext();
		const guest = await visitor.newPage();
		await submitLogin(guest, TEST_USER, TEST_PASS);
		await guest.waitForURL((url) => url.pathname.includes('/wp-admin/'));
		await visitor.close();
	});

	test('the bulk actions block and unblock an account from the users list', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/users.php');

		const row = page.locator(`#the-list tr:has(#user_${userId})`);

		await page.check(`#user_${userId}`);
		await page.selectOption('#bulk-action-selector-top', 'reportedip_block');
		await page.click('#doaction');

		await expect(resultNotice(page, /account\(s\) updated/)).toContainText('1 account(s) updated, 0 skipped.');
		await expect(row.locator('td.rip_account')).toContainText('Blocked');

		await page.check(`#user_${userId}`);
		await page.selectOption('#bulk-action-selector-top', 'reportedip_unblock');
		await page.click('#doaction');

		await expect(resultNotice(page, /account\(s\) updated/)).toContainText('1 account(s) updated, 0 skipped.');
		await expect(row.locator('td.rip_account')).toContainText('Active');
	});

	test('the Sessions page lists a live session and ends it', async ({ page, browser }) => {
		const visitor = await browser.newContext();
		const guest = await visitor.newPage();
		await submitLogin(guest, TEST_USER, TEST_PASS);
		await guest.waitForURL((url) => url.pathname.includes('/wp-admin/'));
		await visitor.close();

		const before = sessionVerifiers(userId);
		expect(before.length).toBeGreaterThan(0);
		const target = before[before.length - 1];

		await loginAsAdmin(page);
		await page.goto('/wp-admin/users.php?page=reportedip-hive-sessions');

		const endButton = page.locator(`button[name="rip_terminate"][value="${userId}:${target}"]`);
		await expect(endButton).toBeVisible();
		await endButton.click();

		await expect(resultNotice(page, /session\(s\) ended/)).toContainText('1 session(s) ended, 0 skipped.');
		expect(sessionVerifiers(userId)).not.toContain(target);
	});

	test('an administrator cannot block their own account', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/profile.php');
		await expect(page.locator('#reportedip-hive-account-access')).toHaveCount(0);

		await page.goto('/wp-admin/users.php');
		const ownRow = page.locator('#the-list tr').filter({ has: page.locator(`.column-username a:text-is("${ADMIN_USER}")`) });
		await ownRow.locator('input[name="users[]"]').check();
		await page.selectOption('#bulk-action-selector-top', 'reportedip_block');
		await page.click('#doaction');

		await expect(resultNotice(page, /account\(s\) updated/)).toContainText('0 account(s) updated, 1 skipped.');
		await expect(ownRow.locator('td.rip_account')).toContainText('Active');
	});
});
