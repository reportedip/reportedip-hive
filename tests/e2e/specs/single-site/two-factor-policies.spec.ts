import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Adaptive 2FA policies (Professional, since 2.1.51): the settings matrix
 * renders one row per trigger, saves through the Settings API, and keeps the
 * administrator column off until an administrator has passed a challenge.
 *
 * The plan is driven through `reportedip_hive_known_tier`, the durable
 * fallback the mode manager reads when no API status transient is present.
 *
 * Serial: the spec mutates the stack's stored tier and policy options.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const POLICY_KEY = 'reportedip_hive_2fa_policy_new_ip';
const LATCH_KEY = 'reportedip_hive_2fa_policy_admin_verified';

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

let twoFactorWasOn = '0';

test.describe.configure({ mode: 'serial' });

test.describe('adaptive 2fa policies', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		wpTolerant('option', 'delete', POLICY_KEY);
		wpTolerant('option', 'delete', LATCH_KEY);
		wp('option', 'update', 'reportedip_hive_known_tier', 'professional');
		// The whole 2FA settings block is inert while the master toggle is off.
		twoFactorWasOn = wpTolerant('option', 'get', 'reportedip_hive_2fa_enabled_global') || '0';
		wp('option', 'update', 'reportedip_hive_2fa_enabled_global', '1');
	});

	test.afterAll(() => {
		wpTolerant('option', 'delete', POLICY_KEY);
		wpTolerant('option', 'delete', LATCH_KEY);
		wpTolerant('option', 'delete', 'reportedip_hive_known_tier');
		wp('option', 'update', 'reportedip_hive_2fa_enabled_global', twoFactorWasOn);
	});

	test('the matrix renders one row per trigger', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		const matrix = page.locator('#rip-2fa-policies');
		await expect(matrix).toBeVisible();
		await expect(matrix.locator('tbody tr')).toHaveCount(7);
		await expect(matrix.locator('input[name="reportedip_hive_2fa_policy_days"]')).toBeVisible();
	});

	test('the administrator column stays off while the latch is closed', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		const adminBox = page
			.locator('#rip-2fa-policies')
			.locator(`input[name="${POLICY_KEY}[]"][value="administrator"]`);

		await expect(adminBox).toBeDisabled();
	});

	test('ticking a role saves the policy list', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		await page
			.locator('#rip-2fa-policies')
			.locator(`input[name="${POLICY_KEY}[]"][value="editor"]`)
			.check();
		await page.locator('#rip-2fa-policies').scrollIntoViewIfNeeded();
		await page.locator('form input[type="submit"], form button[type="submit"]').first().click();

		await expect
			.poll(() => wpTolerant('option', 'get', POLICY_KEY), { timeout: 30_000 })
			.toBe('["editor"]');
	});
});
