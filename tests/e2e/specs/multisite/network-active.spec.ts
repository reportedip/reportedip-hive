import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Smoke test: plugin is network-active on the WPMU stack and the network
 * admin page is reachable. The wpmu-installer one-shot service activates
 * the plugin via WP-CLI on stack-up; if this test fails, the bootstrap
 * did not complete.
 */
test.beforeAll(() => {
    resetAdminBaseline('docker-compose.multisite.yml', 'wordpress-ms');
});

test('reportedip-hive is network-active on WPMU stack', async ({ page }) => {
    await loginAsAdmin(page);

    await page.goto('/wp-admin/network/plugins.php');
    const row = page.locator('tr[data-slug="reportedip-hive"]');
    await expect(row).toBeVisible();
    await expect(row).toHaveClass(/\bactive\b/);
    await expect(row.locator('span.deactivate a')).toContainText(/Network Deactivate/i);
});

test('site admin sees read-only banner on subsite plugin page', async ({ page }) => {
    await loginAsAdmin(page);

    await page.goto('/site-a/wp-admin/admin.php?page=reportedip-hive-site');
    await expect(page).toHaveURL(/site-a\/wp-admin\/admin\.php\?page=reportedip-hive-site/);
});

test('security widget on the network dashboard', async ({ page }) => {
    await loginAsAdmin(page);

    await page.goto('/wp-admin/network/');
    const widget = page.locator('#reportedip_hive_overview');
    await expect(widget).toBeVisible();
    await expect(widget.locator('.rip-dw__meta')).toContainText('Network-wide');
});
