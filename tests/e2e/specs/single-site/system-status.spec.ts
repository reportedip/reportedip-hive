import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The System Status page carries the readiness register (since 2.1.51). The
 * spec proves the section renders under the three health cards on a clean
 * install, whether or not any issue is currently open.
 */

test.beforeAll(() => {
	resetAdminBaseline();
});

test('system status page renders the readiness register', async ({ page }) => {
	await loginAsAdmin(page);
	await page.goto('/wp-admin/admin.php?page=reportedip-hive-debug');

	await expect(page.locator('.rip-header__title')).toBeVisible();

	const readiness = page.locator('#rip-readiness');
	await expect(readiness).toBeVisible();
	await expect(readiness.locator('.rip-settings-section__title')).toContainText('Readiness');
});
