import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The registration rules live on the Network Admin firewall page; a sub-site
 * administrator never sees them. Smoke check that the six cards of the
 * Registration & Spam tab render for the network administrator.
 */

test.beforeAll(() => {
	resetAdminBaseline('docker-compose.multisite.yml', 'wordpress-ms');
});

test('network admin sees every registration card', async ({ page }) => {
	await loginAsAdmin(page);
	await page.goto('/wp-admin/network/admin.php?page=reportedip-hive-firewall&tab=spam');

	await expect(page.locator('.rip-card__header h2', { hasText: 'Disposable Email' })).toBeVisible();

	for (const id of [
		'#rip-reg-usernames',
		'#rip-reg-emails',
		'#rip-reg-limit',
		'#rip-reg-allowlist',
		'#rip-reg-probe',
	]) {
		await expect(page.locator(id)).toBeVisible();
	}
});
