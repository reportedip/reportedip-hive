import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Registration rules (since 2.1.51): the Firewall page writes the prohibited
 * username list through the generic registry writer, and the guard enforces it
 * on the real wp-login registration form.
 *
 * Serial: the spec mutates shared plugin state on the long-lived stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const BLOCKED_LOGIN = 'e2eblockedname';

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

let registrationWasOpen = '0';

test.describe.configure({ mode: 'serial' });

test.describe('registration rules', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		registrationWasOpen = wpTolerant('option', 'get', 'users_can_register') || '0';
		wp('option', 'update', 'users_can_register', '1');
		wpTolerant('option', 'delete', 'reportedip_hive_prohibited_usernames');
	});

	test.afterAll(() => {
		wp('option', 'update', 'users_can_register', registrationWasOpen);
		wpTolerant('option', 'delete', 'reportedip_hive_prohibited_usernames');
	});

	test('the card saves the list and the guard refuses that login', async ({ page, browser }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-firewall&tab=spam');

		const card = page.locator('#rip-reg-usernames');
		await expect(card).toBeVisible();

		await card.locator('textarea[data-opt="reportedip_hive_prohibited_usernames"]').fill(BLOCKED_LOGIN);
		await card.locator('button[data-rip-save]').click();

		await expect
			.poll(() => wpTolerant('option', 'get', 'reportedip_hive_prohibited_usernames'), {
				timeout: 30_000,
			})
			.toBe(BLOCKED_LOGIN);

		const visitor = await browser.newContext();
		const guest = await visitor.newPage();
		await guest.goto('/wp-login.php?action=register');
		await guest.fill('#user_login', BLOCKED_LOGIN);
		await guest.fill('#user_email', `${BLOCKED_LOGIN}@example.org`);
		await guest.click('#wp-submit');

		await expect(guest.locator('#login')).toContainText('This username is not allowed');
		await visitor.close();
	});

	test('the other registration cards render', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-firewall&tab=spam');

		for (const id of ['#rip-reg-emails', '#rip-reg-limit', '#rip-reg-allowlist', '#rip-reg-probe']) {
			await expect(page.locator(id)).toBeVisible();
		}
	});
});
