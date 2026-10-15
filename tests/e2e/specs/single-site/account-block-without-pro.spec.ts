import { execFileSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * Account block without the add-on: a block record written by a 2.x release
 * (or by the add-on before it was removed) keeps the account out of the
 * sign-in form with the free plugin alone, and `wp reportedip user unblock`
 * lifts it without the add-on and without a plan.
 *
 * The record is written the way 2.1.74 stored it. The free suite runs with
 * the add-on inactive.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-suite-wordpress-1';
const BLOCKED = 'rip_e2e_legacy_blocked';
const BLOCKED_PASS = 'RipE2eLegacyBlock!74';
const OPERATOR_TEXT = 'Offboarded under 2.1.74.';

function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], {
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

function wpTolerant(...args: string[]): string {
	try {
		return wp(...args);
	} catch {
		return '';
	}
}

async function submitLogin(page: Page): Promise<void> {
	await page.goto('/wp-login.php');
	await page.fill('#user_login', BLOCKED);
	await page.fill('#user_pass', BLOCKED_PASS);
	await page.click('#wp-submit');
}

test.describe.configure({ mode: 'serial' });

test.describe('account block without the add-on', () => {
	test.skip(process.env.RIP_E2E_WITH_PRO === '1', 'tests the free plugin alone; with the add-on the account block runs through its user-block path (pro suite user-sessions)');
	let threshold = '';

	test.beforeAll(() => {
		threshold = wpTolerant('option', 'get', 'reportedip_hive_failed_login_threshold');
		wpTolerant('user', 'delete', BLOCKED, '--yes');
		const id = wp('user', 'create', BLOCKED, `${BLOCKED}@example.org`, '--role=subscriber', `--user_pass=${BLOCKED_PASS}`, '--porcelain');
		wp(
			'eval',
			`update_user_meta( ${Number(id)}, '_reportedip_hive_blocked', array( 'blocked_at' => gmdate( 'Y-m-d H:i:s' ), 'blocked_by' => 0, 'message' => '${OPERATOR_TEXT}', 'note' => '' ) );`
		);
		wp('option', 'update', 'reportedip_hive_failed_login_threshold', '50');
	});

	test.afterAll(() => {
		wpTolerant('user', 'delete', BLOCKED, '--yes');
		if (threshold === '') {
			wpTolerant('option', 'delete', 'reportedip_hive_failed_login_threshold');
		} else {
			wp('option', 'update', 'reportedip_hive_failed_login_threshold', threshold);
		}
	});

	test('the add-on is inactive', () => {
		expect(wp('plugin', 'status', 'reportedip-hive-pro')).toContain('Inactive');
	});

	test('a stored block refuses the correct password with the block message', async ({ browser }) => {
		const context = await browser.newContext();
		const page = await context.newPage();
		await submitLogin(page);

		await expect(page.locator('#login_error')).toContainText('This account has been blocked.');
		await expect(page.locator('#login_error')).toContainText(OPERATOR_TEXT);
		expect(new URL(page.url()).pathname).toContain('wp-login.php');
		await context.close();
	});

	test('the free command lists and lifts the block', async ({ browser }) => {
		expect(wp('reportedip', 'user', 'list', '--format=csv')).toContain(BLOCKED);
		expect(wp('reportedip', 'user', 'unblock', BLOCKED)).toContain('Unblocked');

		const context = await browser.newContext();
		const page = await context.newPage();
		await submitLogin(page);
		await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));
		await context.close();
	});

	test('the profile card shows the block and lifts it without the add-on', async ({ page, browser }) => {
		const id = Number(wp('user', 'get', BLOCKED, '--field=ID'));
		wp(
			'eval',
			`update_user_meta( ${id}, '_reportedip_hive_blocked', array( 'blocked_at' => gmdate( 'Y-m-d H:i:s' ), 'blocked_by' => 0, 'message' => '${OPERATOR_TEXT}', 'note' => '' ) );`
		);

		await loginAsAdmin(page);
		await page.goto(`/wp-admin/user-edit.php?user_id=${id}`);
		const card = page.locator('#reportedip-hive-account-access + table');
		await expect(card).toContainText('Blocked');
		await expect(card).toContainText(OPERATOR_TEXT);
		await expect(card).not.toContainText(/Business|unl[o]ck/i);
		await Promise.all([page.waitForURL(/updated=1/), card.locator('button[name="rip_account_unblock"]').click()]);
		await expect(page.locator('#reportedip-hive-account-access')).toHaveCount(0);

		const context = await browser.newContext();
		const visitor = await context.newPage();
		await submitLogin(visitor);
		await visitor.waitForURL((url) => url.pathname.includes('/wp-admin/'));
		await context.close();
	});
});
