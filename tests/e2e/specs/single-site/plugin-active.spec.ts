import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Smoke test: plugin is active on the single-site stack and the dashboard
 * loads without fatal errors. Verifies the plugin admin page reachable.
 */
test.beforeAll(() => {
    resetAdminBaseline();
});

test('reportedip-hive admin dashboard renders on single-site', async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto('/wp-admin/admin.php?page=reportedip-hive');

    /*
     * The `h1` fallback this assertion carried until 2.1.65 made it pass on
     * any wp-admin screen, a fatal-error page included. The plugin's own
     * header is the thing that proves the page is ours.
     */
    await expect(page.locator('.rip-header__title')).toBeVisible();
    await expect(page.locator('.rip-dashboard')).toBeVisible();
});
