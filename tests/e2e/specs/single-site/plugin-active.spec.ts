import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * Smoke test: plugin is active on the single-site stack and the dashboard
 * loads without fatal errors. Verifies the plugin admin page reachable.
 */
test('reportedip-hive admin dashboard renders on single-site', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/wp-admin/admin.php?page=reportedip-hive');
    await expect(page.locator('.rip-header__title, h1')).toBeVisible();
});
