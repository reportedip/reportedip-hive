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

/**
 * The sub-site page is the read-only half of the network split: a site
 * admin sees their own numbers and nothing they could change. Asserting the
 * URL alone, which is what this test did until 2.1.65, passed even when the
 * page rendered nothing at all.
 */
test('site admin sees the read-only overview on a subsite', async ({ page }) => {
    await loginAsAdmin(page);

    await page.goto('/site-a/wp-admin/admin.php?page=reportedip-hive-site');

    await expect(page.locator('.rip-header__subtitle')).toContainText(/Site security overview/i);
    await expect(page.locator('.rip-stat-card').first()).toBeVisible();
    await expect(
        page.locator('.rip-content input[type="submit"], .rip-content button[type="submit"]'),
        'the sub-site overview must not offer a way to write'
    ).toHaveCount(0);
});

test('security widget on the network dashboard', async ({ page }) => {
    await loginAsAdmin(page);

    await page.goto('/wp-admin/network/');
    const widget = page.locator('#reportedip_hive_overview');
    await expect(widget).toBeVisible();
    await expect(widget.locator('.rip-dw__meta').first()).toContainText('Network-wide');
});

test('system status page in the network admin shows the readiness register', async ({ page }) => {
    await loginAsAdmin(page);

    await page.goto('/wp-admin/network/admin.php?page=reportedip-hive-debug');
    const readiness = page.locator('#rip-readiness');
    await expect(readiness).toBeVisible();
    await expect(readiness.locator('.rip-settings-section__title')).toContainText('Readiness');

    // The register body renders either the issue table or the empty state; a
    // section with neither means the network-side compute path bailed out.
    const body = readiness.locator('.rip-card__body');
    await expect(body).toBeVisible();
    const rows = await body.locator('table.rip-table tbody tr').count();
    const empty = await body.locator('.rip-help-text', { hasText: 'No open readiness issues' }).count();
    expect(rows + empty).toBeGreaterThan(0);
});
