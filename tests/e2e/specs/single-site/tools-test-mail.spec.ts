import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * Tools page, Diagnostics tab: the test-mail button must fire the AJAX
 * request and show the result. The handler lives in admin.js because the
 * localized `reportedip_hive_ajax` object is printed in the footer.
 */
test.describe('tools page test mail', () => {
	test('send test email reports the result', async ({ page }) => {
		test.setTimeout(240_000);
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-tools&tab=diagnose');

		const ajax = page.waitForResponse((r) => r.url().includes('admin-ajax.php') && r.request().postData()?.includes('reportedip_hive_send_test_mail') === true);
		await page.locator('#reportedip-send-test-mail').click();
		const response = await ajax;
		expect(response.ok()).toBe(true);

		const status = page.locator('#reportedip-send-test-mail-status');
		await expect(status).toBeVisible();
		await expect(status).toContainText('Test email sent to');
	});
});
